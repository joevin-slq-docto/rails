# frozen_string_literal: true

require "active_support/core_ext/object/deep_dup"
require "active_support/core_ext/array/wrap"

module ActionDispatch # :nodoc:
  # # Action Dispatch Content Security Policy
  #
  # Configures the HTTP [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
  # response header to help protect against XSS and
  # injection attacks.
  #
  # Example global policy:
  #
  #     Rails.application.config.content_security_policy do |policy|
  #       policy.default_src :self, :https
  #       policy.font_src    :self, :https, :data
  #       policy.img_src     :self, :https, :data
  #       policy.object_src  :none
  #       policy.script_src  :self, :https
  #       policy.style_src   :self, :https
  #
  #       # Specify URI for violation reports
  #       policy.report_uri "/csp-violation-report-endpoint"
  #     end
  class ContentSecurityPolicy
    class InvalidDirectiveError < StandardError
    end

    class Middleware
      def initialize(app)
        @app = app
      end

      def call(env)
        status, headers, _ = response = @app.call(env)

        # Returning CSP headers with a 304 Not Modified is harmful, since nonces in the
        # new CSP headers might not match nonces in the cached HTML.
        return response if status == 304

        return response if policy_present?(headers)

        request = ActionDispatch::Request.new env
        policy = request.content_security_policy
        policy = inline_content_policy(request, policy) if sandbox_inline_content?(request, headers)

        if policy
          nonce = request.content_security_policy_nonce
          nonce_directives = request.content_security_policy_nonce_directives
          context = request.controller_instance || request
          header = policy.build(context, nonce, nonce_directives)
          headers[header_name(request)] = header unless header.empty?
        end

        response
      end

      private
        def sandbox_inline_content?(request, headers)
          # Browsers ignore `sandbox` in a report-only policy.
          return false if request.content_security_policy_report_only

          headers[ActionDispatch::Constants::CONTENT_DISPOSITION]&.match?(/\Ainline\b/i)
        end

        def inline_content_policy(request, policy)
          sandbox = request.get_header("action_dispatch.sandbox_inline_content")
          policy ||= ContentSecurityPolicy.new if sandbox
          policy&.for_inline_content(sandbox)
        end

        def header_name(request)
          if request.content_security_policy_report_only
            ActionDispatch::Constants::CONTENT_SECURITY_POLICY_REPORT_ONLY
          else
            ActionDispatch::Constants::CONTENT_SECURITY_POLICY
          end
        end

        def policy_present?(headers)
          headers[ActionDispatch::Constants::CONTENT_SECURITY_POLICY] ||
            headers[ActionDispatch::Constants::CONTENT_SECURITY_POLICY_REPORT_ONLY]
        end
    end

    module Request
      POLICY = "action_dispatch.content_security_policy"
      POLICY_REPORT_ONLY = "action_dispatch.content_security_policy_report_only"
      NONCE_GENERATOR = "action_dispatch.content_security_policy_nonce_generator"
      NONCE = "action_dispatch.content_security_policy_nonce"
      NONCE_DIRECTIVES = "action_dispatch.content_security_policy_nonce_directives"

      def content_security_policy
        get_header(POLICY)
      end

      def content_security_policy=(policy)
        set_header(POLICY, policy)
      end

      def content_security_policy_report_only
        get_header(POLICY_REPORT_ONLY)
      end

      def content_security_policy_report_only=(value)
        set_header(POLICY_REPORT_ONLY, value)
      end

      def content_security_policy_nonce_generator
        get_header(NONCE_GENERATOR)
      end

      def content_security_policy_nonce_generator=(generator)
        set_header(NONCE_GENERATOR, generator)
      end

      def content_security_policy_nonce_directives
        get_header(NONCE_DIRECTIVES)
      end

      def content_security_policy_nonce_directives=(generator)
        set_header(NONCE_DIRECTIVES, generator)
      end

      def content_security_policy_nonce
        if content_security_policy_nonce_generator
          if nonce = get_header(NONCE)
            nonce
          else
            set_header(NONCE, generate_content_security_policy_nonce)
          end
        end
      end

      private
        def generate_content_security_policy_nonce
          content_security_policy_nonce_generator.call(self)
        end
    end

    MAPPINGS = {
      self:             "'self'",
      unsafe_eval:      "'unsafe-eval'",
      wasm_unsafe_eval: "'wasm-unsafe-eval'",
      unsafe_hashes:    "'unsafe-hashes'",
      unsafe_inline:    "'unsafe-inline'",
      none:             "'none'",
      http:             "http:",
      https:            "https:",
      data:             "data:",
      mediastream:      "mediastream:",
      allow_duplicates: "'allow-duplicates'",
      blob:             "blob:",
      filesystem:       "filesystem:",
      report_sample:    "'report-sample'",
      script:           "'script'",
      strict_dynamic:   "'strict-dynamic'",
      ws:               "ws:",
      wss:              "wss:"
    }.freeze

    DIRECTIVES = {
      base_uri:                   "base-uri",
      child_src:                  "child-src",
      connect_src:                "connect-src",
      default_src:                "default-src",
      font_src:                   "font-src",
      form_action:                "form-action",
      frame_ancestors:            "frame-ancestors",
      frame_src:                  "frame-src",
      img_src:                    "img-src",
      manifest_src:               "manifest-src",
      media_src:                  "media-src",
      object_src:                 "object-src",
      prefetch_src:               "prefetch-src",
      require_trusted_types_for:  "require-trusted-types-for",
      script_src:                 "script-src",
      script_src_attr:            "script-src-attr",
      script_src_elem:            "script-src-elem",
      style_src:                  "style-src",
      style_src_attr:             "style-src-attr",
      style_src_elem:             "style-src-elem",
      trusted_types:              "trusted-types",
      worker_src:                 "worker-src"
    }.freeze

    HASH_SOURCE_ALGORITHM_PREFIXES = ["sha256-", "sha384-", "sha512-"].freeze

    DEFAULT_NONCE_DIRECTIVES = %w[script-src style-src].freeze

    private_constant :MAPPINGS, :DIRECTIVES, :DEFAULT_NONCE_DIRECTIVES

    attr_reader :directives

    def initialize
      @directives = {}
      @sandbox_inline_content = nil
      yield self if block_given?
    end

    def initialize_copy(other)
      @directives = other.directives.deep_dup
    end

    DIRECTIVES.each do |name, directive|
      define_method(name) do |*sources|
        if sources.first
          @directives[directive] = apply_mappings(sources)
        else
          @directives.delete(directive)
        end
      end
    end

    # Specify whether to prevent the user agent from loading any assets over HTTP
    # when the page uses HTTPS:
    #
    #     policy.block_all_mixed_content
    #
    # Pass `false` to allow it again:
    #
    #     policy.block_all_mixed_content false
    #
    def block_all_mixed_content(enabled = true)
      if enabled
        @directives["block-all-mixed-content"] = true
      else
        @directives.delete("block-all-mixed-content")
      end
    end

    # Restricts the set of plugins that can be embedded:
    #
    #     policy.plugin_types "application/x-shockwave-flash"
    #
    # Leave empty to allow all plugins:
    #
    #     policy.plugin_types
    #
    def plugin_types(*types)
      if types.first
        @directives["plugin-types"] = types
      else
        @directives.delete("plugin-types")
      end
    end

    # Enable the [report-uri](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri)
    # directive. Violation reports will be sent to the
    # specified URI:
    #
    #     policy.report_uri "/csp-violation-report-endpoint"
    #
    def report_uri(uri)
      @directives["report-uri"] = [uri]
    end

    # Specify asset types for which [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity) is required:
    #
    #     policy.require_sri_for :script, :style
    #
    # Leave empty to not require Subresource Integrity:
    #
    #     policy.require_sri_for
    #
    def require_sri_for(*types)
      if types.first
        @directives["require-sri-for"] = types
      else
        @directives.delete("require-sri-for")
      end
    end

    # Specify whether a [sandbox](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/sandbox)
    # should be enabled for the requested resource:
    #
    #     policy.sandbox
    #
    # Values can be passed as arguments:
    #
    #     policy.sandbox "allow-scripts", "allow-modals"
    #
    # Pass `false` to disable the sandbox:
    #
    #     policy.sandbox false
    #
    def sandbox(*values)
      if values.empty?
        @directives["sandbox"] = true
      elsif values.first
        @directives["sandbox"] = values
      else
        @directives.delete("sandbox")
      end
    end

    # Specify the [sandbox](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/sandbox)
    # of the content served inline, that is the responses whose
    # `Content-Disposition` is `inline`. The policy of the other responses is left
    # alone:
    #
    #     policy.sandbox_inline_content
    #
    # Values can be passed as arguments:
    #
    #     policy.sandbox_inline_content "allow-scripts", "allow-modals"
    #
    # Pass `false` to disable the sandbox:
    #
    #     policy.sandbox_inline_content false
    #
    # For these responses, it takes precedence over #sandbox. When it is not
    # called, `config.action_dispatch.sandbox_inline_content` decides whether the
    # content served inline is sandboxed.
    def sandbox_inline_content(*values)
      if values.empty? || values.first == true
        @sandbox_inline_content = true
      elsif values.first
        @sandbox_inline_content = values
      else
        @sandbox_inline_content = false
      end
    end

    # Specify whether user agents should treat any assets over HTTP as HTTPS:
    #
    #     policy.upgrade_insecure_requests
    #
    # Pass `false` to disable it:
    #
    #     policy.upgrade_insecure_requests false
    #
    def upgrade_insecure_requests(enabled = true)
      if enabled
        @directives["upgrade-insecure-requests"] = true
      else
        @directives.delete("upgrade-insecure-requests")
      end
    end

    def build(context = nil, nonce = nil, nonce_directives = nil)
      nonce_directives = DEFAULT_NONCE_DIRECTIVES if nonce_directives.nil?
      build_directives(context, nonce, nonce_directives).compact.join("; ")
    end

    # Returns the policy of the content served inline: this policy with the
    # `sandbox` directive of #sandbox_inline_content.
    def for_inline_content(sandbox_by_default = false) # :nodoc:
      sandbox = @sandbox_inline_content.nil? ? sandbox_by_default : @sandbox_inline_content
      return self unless sandbox

      sandbox = Array(sandbox) unless sandbox == true
      clone.tap { |policy| policy.directives["sandbox"] = sandbox }
    end

    private
      def apply_mappings(sources)
        sources.map do |source|
          case source
          when Symbol
            apply_mapping(source)
          when String
            if hash_source?(source)
              "'#{source}'"
            else
              source
            end
          when Proc
            source
          else
            raise ArgumentError, "Invalid content security policy source: #{source.inspect}"
          end
        end
      end

      def apply_mapping(source)
        MAPPINGS.fetch(source) do
          raise ArgumentError, "Unknown content security policy source mapping: #{source.inspect}"
        end
      end

      def build_directives(context, nonce, nonce_directives)
        @directives.map do |directive, sources|
          if sources.is_a?(Array)
            if nonce && nonce_directive?(directive, nonce_directives)
              "#{directive} #{build_directive(directive, sources, context).join(' ')} 'nonce-#{nonce}'"
            else
              "#{directive} #{build_directive(directive, sources, context).join(' ')}"
            end
          elsif sources
            directive
          else
            nil
          end
        end
      end

      def validate(directive, sources)
        sources.each do |source|
          if source.include?(";") || source.match?(/[[:space:]]/)
            raise InvalidDirectiveError, <<~MSG.squish
              Invalid Content Security Policy #{directive}: "#{source}".
              Directive values must not contain whitespace or semicolons.
              Please use multiple arguments or other directive methods instead.
            MSG
          end
        end
      end

      def build_directive(directive, sources, context)
        resolved_sources = sources.flat_map { |source| resolve_source(source, context) }

        validate(directive, resolved_sources)

        resolved_sources
      end

      def resolve_source(source, context)
        case source
        when String
          source
        when Symbol
          source.to_s
        when Proc
          if context.nil?
            raise RuntimeError, "Missing context for the dynamic content security policy source: #{source.inspect}"
          else
            resolved = context.instance_exec(&source)
            apply_mappings(Array.wrap(resolved))
          end
        else
          raise RuntimeError, "Unexpected content security policy source: #{source.inspect}"
        end
      end

      def nonce_directive?(directive, nonce_directives)
        nonce_directives.include?(directive)
      end

      def hash_source?(source)
        source.start_with?(*HASH_SOURCE_ALGORITHM_PREFIXES)
      end
  end
end

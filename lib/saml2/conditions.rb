require 'active_support/core_ext/array/wrap'

module SAML2
  class Conditions < Array
    attr_accessor :not_before, :not_on_or_after

    def valid?(options = {})
      now = options[:now] || Time.now
      return :invalid if not_before && now < not_before
      return :invalid if not_on_or_after && now >= not_on_or_after

      result = :valid
      each do |condition|
        this_result = condition.valid?(options)
        case this_result
        when :invalid
          return :invalid
        when :indeterminate
          result = :indeterminate
          when :valid
        else
          raise "unknown validity of #{condition}"
        end
      end
      result
    end

    def build(builder)
      builder['saml'].Conditions do |builder|
        builder.parent['NotBefore'] = not_before.iso8601 if not_before
        builder.parent['NotOnOrAfter'] = not_on_or_after.iso8601 if not_on_or_after

        each do |condition|
          condition.build(builder)
        end
      end
    end

    # Any unknown condition
    class Condition
      def valid?(_)
        :indeterminate
      end
    end

    class AudienceRestriction < Condition
      attr_accessor :audience

      def initialize(audience)
        @audience = audience
      end

      def valid?(options)
        Array.wrap(audience).include?(options[:audience]) ? :valid : :invalid
      end

      def build(builder)
        builder['saml'].AudienceRestriction do |builder|
          Array.wrap(audience).each do |single_audience|
            builder['saml'].Audience(single_audience)
          end
        end
      end
    end

    class OneTimeUse < Condition
      def valid?(_)
        :valid
      end

      def build(builder)
        builder['saml'].OneTimeUse
      end
    end
  end
end

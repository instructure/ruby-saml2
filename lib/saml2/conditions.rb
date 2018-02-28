require 'active_support/core_ext/array/wrap'

module SAML2
  class Conditions < Array
    # @return [Time, nil]
    attr_accessor :not_before, :not_on_or_after
    # (see Base#xml)
    attr_reader :xml

    # (see Base.from_xml)
    def self.from_xml(node)
      result = new
      result.from_xml(node)
      result
    end

    # (see Base#from_xml)
    def from_xml(node)
      @xml = node
      @not_before = Time.parse(node['NotBefore']) if node['NotBefore']
      @not_on_or_after = Time.parse(node['NotOnOrAfter']) if node['NotOnOrAfter']

      replace(node.children.map { |restriction| self.class.const_get(restriction.name, false).from_xml(restriction) })
    end

    # Evaluate these conditions.
    #
    # @todo change to [true, false, nil] return
    # @param now optional [Time]
    # @param options
    #   Additional options to pass to specific {Condition}s
    # @return [:valid, :invalid, :indeterminate]
    #   It's only valid if every sub-condition is completely valid.
    #   If any sub-condition is invalid, the whole statement is invalid.
    def valid?(now: Time.now.utc, **options)
      options[:now] ||= now
      return :invalid if not_before && now < not_before
      return :invalid if not_on_or_after && now >= not_on_or_after

      result = :valid
      each do |condition|
        this_result = condition.valid?(**options)
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

    # (see Base#build)
    def build(builder)
      builder['saml'].Conditions do |conditions|
        conditions.parent['NotBefore'] = not_before.iso8601 if not_before
        conditions.parent['NotOnOrAfter'] = not_on_or_after.iso8601 if not_on_or_after

        each do |condition|
          condition.build(conditions)
        end
      end
    end

    # Any unknown condition
    class Condition < Base
      def valid?(_)
        :indeterminate
      end
    end

    class AudienceRestriction < Condition
      attr_writer :audience

      # @param audience [Array<String>]
      def initialize(audience = [])
        @audience = audience
      end

      # (see Base#from_xml)
      def from_xml(node)
        super
        @audience = nil
      end

      # @return [Array<String>] Allowed audiences
      def audience
        @audience ||= load_string_array(xml, 'saml:Audience')
      end

      # @param audience [String]
      def valid?(audience: nil, **_)
        Array.wrap(self.audience).include?(audience) ? :valid : :invalid
      end

      # (see Base#build)
      def build(builder)
        builder['saml'].AudienceRestriction do |audience_restriction|
          Array.wrap(audience).each do |single_audience|
            audience_restriction['saml'].Audience(single_audience)
          end
        end
      end
    end

    class OneTimeUse < Condition
      def valid?(_)
        :valid
      end

      # (see Base#build)
      def build(builder)
        builder['saml'].OneTimeUse
      end
    end
  end
end

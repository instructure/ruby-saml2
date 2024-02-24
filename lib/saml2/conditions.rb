# frozen_string_literal: true

require "active_support/core_ext/array/wrap"

module SAML2
  class Conditions < Array
    # @return [Time, nil]
    attr_accessor :not_before, :not_on_or_after
    # (see Base#xml)
    attr_reader :xml

    # (see Base.from_xml)
    def self.from_xml(node)
      return nil unless node

      result = new
      result.from_xml(node)
      result
    end

    # (see Base#from_xml)
    def from_xml(node)
      @xml = node
      @not_before = Time.parse(node["NotBefore"]) if node["NotBefore"]
      @not_on_or_after = Time.parse(node["NotOnOrAfter"]) if node["NotOnOrAfter"]

      replace(node.element_children.map do |restriction|
        klass = if self.class.const_defined?(restriction.name, false)
                  self.class.const_get(restriction.name, false)
                else
                  Condition
                end
        klass.from_xml(restriction)
      end)
    end

    # Evaluate these conditions.
    #
    # @param verification_time optional [Time]
    # @param options
    #   Additional options to pass to specific {Condition}s
    # @return [Array<>]
    #   It's only valid if every sub-condition is completely valid.
    #   If any sub-condition is invalid, the whole statement is invalid.
    #   If the validity can't be determined due to an unsupported condition,
    #   +nil+ will be returned (which is false-ish)
    def validate(verification_time: Time.now.utc, **options)
      options[:verification_time] ||= verification_time
      errors = []
      if not_before && verification_time < not_before
        errors << "not_before #{not_before} is later than now (#{verification_time})"
      end
      if not_on_or_after && verification_time >= not_on_or_after
        errors << "not_on_or_after #{not_on_or_after} is earlier than now (#{verification_time})"
      end

      each do |condition|
        errors.concat(condition.validate(**options))
      end
      errors
    end

    # Use validate instead.
    # @deprecated
    def valid?(now: Time.now.utc, **options)
      validate(verification_time: now, **options).empty?
    end

    # (see Base#build)
    def build(builder)
      builder["saml"].Conditions do |conditions|
        conditions.parent["NotBefore"] = not_before.iso8601 if not_before
        conditions.parent["NotOnOrAfter"] = not_on_or_after.iso8601 if not_on_or_after

        each do |condition|
          condition.build(conditions)
        end
      end
    end

    # Any unknown condition
    class Condition < Base
      # @return []
      def validate(_)
        ["unable to validate #{xml&.name || "unrecognized"} condition"]
      end

      def valid?(...)
        validate(...).empty?
      end
    end

    class AudienceRestriction < Condition
      attr_writer :audience

      # @param audience [Array<String>]
      def initialize(audience = [])
        super()
        @audience = audience
      end

      # (see Base#from_xml)
      def from_xml(node)
        super
        @audience = nil
      end

      # @return [Array<String>] Allowed audiences
      def audience
        @audience ||= load_string_array(xml, "saml:Audience")
      end

      # @param audience [String]
      def validate(audience: nil, ignore_audience_condition: false, **_)
        return [] if ignore_audience_condition

        unless Array.wrap(self.audience).include?(audience)
          return ["audience #{audience} not in allowed list of #{Array.wrap(self.audience).join(", ")}"]
        end

        []
      end

      # (see Base#build)
      def build(builder)
        builder["saml"].AudienceRestriction do |audience_restriction|
          Array.wrap(audience).each do |single_audience|
            audience_restriction["saml"].Audience(single_audience)
          end
        end
      end
    end

    class OneTimeUse < Condition
      # The caller will need to see if this condition exists, and validate it
      # using their own state store.
      # @return [[]]
      def validate(_)
        []
      end

      # (see Base#build)
      def build(builder)
        builder["saml"].OneTimeUse
      end
    end
  end
end

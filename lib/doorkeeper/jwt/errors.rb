# frozen_string_literal: true

module Doorkeeper
  module JWT
    # Base class for every error raised by doorkeeper-jwt.
    class Error < StandardError; end

    # Raised when a signing key is configured but `signing_method` is not, so
    # the only token that could be issued would be an unsigned (alg: none) one.
    class SigningMethodMissing < Error; end
  end
end

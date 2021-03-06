require 'threatinator/model/collection'

module Threatinator
  module Model
    module Observables
      class FqdnCollection < Threatinator::Model::Collection
        def valid_member?(v)
          v.is_a?(::String)
        end
      end
    end
  end
end

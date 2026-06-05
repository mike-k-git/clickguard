defmodule Clickguard.Reporter do
  @moduledoc """
  Behaviour for reporters.

  Implementations:

    * `Clickguard.Reporter.Text` - plain text without styling, best for text files and terminal output.

  ## Implementing a reporter

    defmodule MyReporter do
      @behaviour Clickguard.Reporter

      @impl true
      def format(scores) do
        # ...
      end
    end
  """
  alias Clickguard.Score

  @callback format(scores :: [Score.t()]) :: iodata()
end

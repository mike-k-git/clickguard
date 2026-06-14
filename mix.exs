defmodule Clickguard.MixProject do
  use Mix.Project

  def project do
    [
      app: :clickguard,
      version: "0.2.0",
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      escript: escript(),
      dialyzer: [
        plt_file: {:no_warn, "priv/plts/project.plt"},
        plt_add_apps: [:mix]
      ],
      elixirc_paths: elixirc_paths(Mix.env())
    ]
  end

  defp escript do
    [main_module: Clickguard.CLI]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end
end

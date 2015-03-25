defmodule Matasano.Mixfile do
  use Mix.Project

  def project do
    [app: :matasano,
     version: "0.0.1",
     elixir: "~> 1.0",
     name: "Matasano Crypto Challenges in Elixir",
     source_url: "https://github.com/elasticdog/matasano-elixir",
     homepage_url: "https://elasticdog.github.io/matasano-elixir",
     deps: deps]
  end

  # Configuration for the OTP application
  #
  # Type `mix help compile.app` for more information
  def application do
    [applications: [:logger]]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type `mix help deps` for more examples and options
  defp deps do
    [{:earmark, "~> 0.1", only: :dev},
     {:ex_doc, "~> 0.7", only: :dev},
     {:exprof, "~> 0.2", only: :dev}]
  end
end

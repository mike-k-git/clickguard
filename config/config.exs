import Config

config :clickguard,
  detectors: [
    Clickguard.Detector.FreqIp,
    Clickguard.Detector.UserAgent,
    Clickguard.Detector.Referer
  ]

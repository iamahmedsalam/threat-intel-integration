import yaml


def load_config(path="config/config.yaml"):
    file = open(path, "r")
    config = yaml.safe_load(file)
    file.close()
    return config


if __name__ == "__main__":
    config = load_config()
    print("Config loaded successfully")
    print(f"AbuseIPDB URL: {config['abuseipdb']['url']}")
    print(f"Block threshold: {config['thresholds']['block_score']}")
    print(f"Log file: {config['logging']['file']}")

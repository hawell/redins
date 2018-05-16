package config

import (
    "encoding/json"
    "io/ioutil"
    "log"
)

type ServerConfig struct {
    Ip       string `json:"ip,omitempty"`
    Port     int `json:"port,omitempty"`
    Protocol string `json:"protocol,omitempty"`
}

type HandlerConfig struct {
    DefaultTtl int `json:"default_ttl,omitempty"`
    CacheTimeout int `json:"cache_timeout,omitempty"`
    ZoneReload int `json:"zone_reload,omitempty"`
    Redis RedisConfig `json:"redis,omitempty"`
    Log LogConfig `json:"log,omitempty"`
}

type UpstreamConfig struct {
    Enable bool `json:"enable,omitempty"`
    Ip       string `json:"ip,omitempty"`
    Port     int `json:"port,omitempty"`
    Protocol string `json:"protocol,omitempty"`
}

type GeoIpConfig struct {
    Enable bool `json:"enable,omitempty"`
    Db string `json:"db,omitempty"`
    Log LogConfig `json:"log,omitempty"`
}

type HealthcheckConfig struct {
    Enable bool `json:"enable,omitempty"`
    MaxRequests int `json:"max_requests,omitempty"`
    UpdateInterval int `json:"update_interval,omitempty"`
    CheckInterval int `json:"check_interval,omitempty"`
    Redis RedisConfig `json:"redis,omitempty"`
    Log LogConfig `json:"log,omitempty"`

}

type RedisConfig struct {
    Ip string `json:"ip,omitempty"`
    Port int `json:"port,omitempty"`
    Password string `json:"password,omitempty"`
    Prefix string `json:"prefix,omitempty"`
    Suffix string `json:"suffix,omitempty"`
    ConnectTimeout int `json:"connect_timeout,omitempty"`
    ReadTimeout int `json:"read_timeout,omitempty"`
}

type LogConfig struct {
    Enable bool `json:"enable,omitempty"`
    Path string `json:"path,omitempty"`
}

type RedinsConfig struct {
    Server ServerConfig `json:"server,omitempty"`
    Handler HandlerConfig `json:"handler,omitempty"`
    Upstream UpstreamConfig `json:"upstream,omitempty"`
    GeoIp GeoIpConfig `json:"geoip,omitempty"`
    HealthCheck HealthcheckConfig `json:"healthcheck,omitempty"`
}


func LoadConfig(path string) *RedinsConfig {
    config := &RedinsConfig {
        Server: ServerConfig {
            Ip: "127.0.0.1",
            Port: 1053,
            Protocol: "udp",
        },
        Handler: HandlerConfig {
            DefaultTtl: 300,
            CacheTimeout: 60,
            ZoneReload: 600,
            Redis: RedisConfig {
              Ip: "127.0.0.1",
              Port: 6379,
              Password: "",
              Prefix: "redins_",
              Suffix: "_redins",
              ConnectTimeout: 0,
              ReadTimeout: 0,
            },
            Log: LogConfig {
                Enable: true,
                Path: "/tmp/redins.log",
            },
        },
        Upstream: UpstreamConfig {
            Enable: false,
            Ip: "1.1.1.1",
            Port: 53,
            Protocol: "udp",
        },
        GeoIp: GeoIpConfig {
            Enable: false,
            Db: "geoCity.mmdb",
            Log: LogConfig {
                Enable: false,
                Path: "/tmp/geoip.log",
            },
        },
        HealthCheck: HealthcheckConfig {
            Enable: false,
            MaxRequests: 10,
            UpdateInterval: 600,
            CheckInterval: 600,
            Redis: RedisConfig {
                Ip: "127.0.0.1",
                Port: 6379,
                Password: "",
                Prefix: "redins_",
                Suffix: "_redins",
                ConnectTimeout: 0,
                ReadTimeout: 0,
            },
            Log: LogConfig {
                Enable: true,
                Path: "/tmp/healthcheck.log",
            },
        },
    }
    raw, err := ioutil.ReadFile(path)
    if err != nil {
        log.Printf("[ERROR] cannot load file %s : %s", path, err)
        log.Printf("[INFO] loading default config")
        return config
    }
    err = json.Unmarshal(raw, config)
    if err != nil {
        log.Printf("[ERROR] cannot load json file")
        log.Printf("[INFO] loading default config")
        return config
    }
    return config
}
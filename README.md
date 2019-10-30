[![Build Status](https://img.shields.io/travis/arvancloud/redins.svg)](https://travis-ci.org/arvancloud/redins)
[![Code Coverage](https://img.shields.io/codecov/c/github/arvancloud/redins.svg)](https://codecov.io/github/arvancloud/redins?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/arvancloud/redins)](https://goreportcard.com/report/arvancloud/redins)

# table of contents

- [Configuration](#configuration)
    - [server](#server)
    - [handler](#handler)
    - [healthcheck](#healthcheck)
    - [geoip](#geoip)
    - [upstream](#upstream)
    - [error log](#error_log)
    - [redis](#redis)
    - [log](#log)
    - [rate limit](#rate-limit)
    - [example](#example)
- [Zone format in redis](#zone-format-in-redis-db)
    - [keys](#keys)
    - [zones](#zones)
    - [dns RRs](#dns-rrs)
        - [A](#a)
        - [AAAA](#aaaa)
        - [ANAME](#aname)
        - [CNAME](#cname)
        - [TXT](#txt)
        - [NS](#ns)
        - [MX](#mx)
        - [SRV](#srv)
        - [CAA](#caa)
        - [PTR](#ptr)
        - [TLSA](#tlsa)
    - [example](#zone-example)
    

*redins* enables reading zone data from redis database.

## Configuration

### server
dns listening server configuration

~~~json
{
  "server": {
    "ip": "127.0.0.1",
    "port": 1053,
    "protocol": "udp"
  }
}
~~~

* `ip` : ip address to bind, default: 127.0.0.1
* `port` : port number to bind, default: 1053
* `protocol` : protocol; can be tcp or udp, default: udp

### handler
dns query handler configuration

~~~json
{
"handler": {
    "max_ttl": 300,
    "cache_timeout": 60,
    "zone_reload": 600,
    "log_source_location": false,
    "upstream_fallback": false,
    "redis": {
        "ip": "127.0.0.1",
        "port": 6379,
        "password": "",
        "db": 0,
        "prefix": "test_",
        "suffix": "_test"
    },
    "log": {
    "enable": true,
    "level": "info",
    "target": "file",
    "format": "json",
    "path": "/tmp/redins.log"
    },
    "healthcheck": {
        "enable": true,
        "max_requests": 10,
        "update_interval": 600,
        "check_interval": 600,
        "redis": {
            "ip": "127.0.0.1",
            "port": 6379,
            "db": 0,
            "password": "",
            "prefix": "healthcheck_",
            "suffix": "_healthcheck"
        },
        "log": {
            "enable": true,
            "level": "info",
            "target": "file",
            "format": "json",
            "path": "/tmp/healthcheck.log"
        }
    },
    "geoip": {
        "enable": true,
        "country_db": "geoCity.mmdb",
        "asn_db": "geoIsp.mmdb"
    },
    "upstream": [{
        "ip": "1.1.1.1",
        "port": 53,
        "protocol": "udp",
        "timeout": 400
    }]
  }
}
~~~

* `max_ttl` : max ttl in seconds, default: 3600
* `cache_timeout` : time in seconds before cached responses expire
* `zone_reload` : time in seconds before zone data is reloaded from redis
* `log_source_location` : enable logging source location of every request
* `upstream_fallback` : enable using upstream for querying non-authoritative requests
* `redis` : redis configuration to use for handler
* `log` : log configuration to use for handler

### healthcheck
healthcheck configuration

~~~json
{
  "healthcheck": {
    "enable": true,
    "max_requests": 10,
    "max_pending_requests": 100,
    "update_interval": 600,
    "check_interval": 600,
    "redis": {
      "ip": "127.0.0.1",
      "port": 6379,
      "db": 0,
      "password": "",
      "prefix": "healthcheck_",
      "suffix": "_healthcheck"
    },
    "log": {
      "enable": true,
      "level": "info",
      "target": "file",
      "format": "json",
      "path": "/tmp/healthcheck.log"
    }
  }
}
~~~

* `enable` : enable/disable healthcheck, default: disable
* `max_requests` : maximum number of simultanous healthcheck requests, deafult: 10
* `max_pending_requests` : maximum number of requests to queue, default: 100
* `update_interval` : time between checking for updated data from redis in seconds, default: 300
* `check_interval` : time between two healthcheck requests in seconds, default: 600
* `redis` : redis configuration to use for healthcheck stats
* `log` : log configuration to use for healthcheck logs

### geoip
geoip configuration

~~~json
{
  "geoip": {
    "enable": true,
    "country_db": "geoCity.mmdb",
    "asn_db": "geoIsp.mmdb"
  }
}
~~~

* `enable` : enable/disable geoip calculations, default: disable
* `country_db` : maxminddb file for country codes to use, default: geoCity.mmdb
* `asn_db` : maxminddb file for autonomous system numbers to use, default: geoIsp.mmdb

### upstream

~~~json
{
  "upstream": [{
    "ip": "1.1.1.1",
    "port": 53,
    "protocol": "udp",
    "timeout": 400
  }]
}
~~~

* `ip` : upstream ip address, default: 1.1.1.1
* `port` : upstream port number, deafult: 53
* `protocol` : upstream protocol, default : udp
* `timeout` : request timeout in milliseconds, default: 400

### error_log
log configuration for error, debug, ... messages

~~~json
{
  "log": {
    "enable": true,
    "level": "info",
    "target": "file",
    "format": "json",
    "path": "/tmp/redins.log"
  }
}
~~~

### redis
redis configurations

~~~json
{
  "redis": {
    "ip": "127.0.0.1",
    "port": 6379,
    "db": 0,
    "password": "",
    "prefix": "test_",
    "suffix": "_test",
    "connection": {
      "max_idle_connections": 10,
      "max_active_connections": 10,
      "connect_timeout": 500,
      "read_timeout": 500,
      "idle_keep_alive": 30,
      "max_keep_alive": 0,
      "wait_for_connection": false
    },
    "connect_timeout": 0,
    "read_timeout": 0
  }
}
~~~

* `ip` : redis server ip, default: 127.0.0.1
* `port` : redis server port, deafult: 6379
* `db` : redis database, default: 0
* `password` : redis password, deafult: ""
* `prefix` : limit redis keys to those prefixed with this string
* `suffix` : limit redis keys to those suffixed with this string
* `max_idle_connections`: maximum number of idle connections that pool keeps, default: 10
* `max_active_connections`: maximum number of active connections, default: 10
* `connect_timeout`: time to wait for connecting to redis server in milliseconds, 0 for no timeout; default: 500
* `read_timeout`: time to wait for redis query results in milliseconds, 0 for no timeout; default: 500
* `idle_keep_alive`: time to keep idle connections in seconds, 0 for unlimited; default: 30
* `max_keep_alive`: maximum time to keep a connection in seconds, 0 for unlimited; default: 0
* `wait_for_connection`: whether or not wait for a connection to be available if connection pool is full, default: false

### log
log configuration

~~~json
{
  "log": {
    "enable": true,
    "level": "info",
    "target": "file",
    "format": "json",
    "time_format": "2006-01-02T15:04:05.999999-07:00",
    "path": "/tmp/redins.log",
    "sentry": {
      "enable": false,
      "dsn": ""
    },
    "syslog": {
      "enable": false,
      "protocol": "udp",
      "address": "localhost:514"
    },
    "kafka": {
      "enable": false,
      "brokers": ["127.0.0.1:9092"],
      "topic": "redins",
      "format": "capnp_request",
      "compression": "none",
      "timeout": 3000,
      "buffer_size": 1000
    }
  }
}
~~~

* `enable` : enable/disable this log resource, default: disable
* `level` : log level, can be debug, info, warning, error, default: info
* `target` : log target, can be stdout, stderr, file, default: stdout
* `format` : log format, can be text, json, default: text. an extra log format ("capnp_request") is also available for request logs
* `time_format` : timestamp format using example-based layout, reference time is Mon Jan 2 15:04:05 MST 2006
* `path` : log output file path
* `sentry` : sentry hook configurations
* `syslog` : syslog hook configurations
* `kafka` : kafka hook configurations
    * `enable`: enable/disable kafka hook, default: disable
    * `brokers`: list of brokers in "ip:port" format, default : "127.0.0.1:9092"
    * `topic`: name of kafka topic, default : "redins"
    * `format`: message format, default: "json"
    * `compression`: compression format : "snappy", "gzip", "lz4", "zstd", "none", default: "none"
    * `timeout`: kafka operation timeout (dial, read, write) in milliseconds, default : 3000
    * `buffer_size`: kafka producer buffer size, default : 1000

### rate limit 
rate limit connfiguration

~~~json
{
  "ratelimit": {
    "enable": true,
    "rate": 60,
    "burst": 10,
    "blacklist": ["10.10.10.1"],
    "whitelist": ["127.0.0.1"]
  }
}
~~~

* `enable` : enable/disable rate limit
* `rate` : maximum allowed request per minute
* `burst` : number of burst requests
* `blacklist` : list of ips to refuse all request
* `whitelist` : list of ips to bypass rate limit

### example
sample config:

~~~json
{
  "server": {
      "ip": "127.0.0.1",
      "port": 1053,
      "protocol": "udp"
    },
  "handler": {
    "max_ttl": 300,
    "cache_timeout": 60,
    "zone_reload": 600,
    "log_source_location": false,
    "upstream_fallback": false,
    "redis": {
      "ip": "127.0.0.1",
      "port": 6379,
      "password": "",
      "prefix": "test_",
      "suffix": "_test",
      "connection": {
        "max_idle_connections": 10,
        "max_active_connections": 10,
        "connect_timeout": 500,
        "read_timeout": 500,
        "idle_keep_alive": 30,
        "max_keep_alive": 60,
        "wait_for_connection": false
      }
    },
    "log": {
      "enable": true,
      "level": "info",
      "target": "file",
      "format": "json",
      "path": "/tmp/redins.log"
    },
    "upstream": {
      "ip": "1.1.1.1",
      "port": 53,
      "protocol": "udp"
    },
    "geoip": {
      "enable": true,
      "country_db": "geoCity.mmdb",
      "asn_db": "geoIsp.mmdb"
    },
    "healthcheck": {
      "enable": true,
      "max_requests": 10,
      "max_pending_requests": 100,
      "update_interval": 600,
      "check_interval": 600,
      "redis": {
        "ip": "127.0.0.1",
        "port": 6379,
        "password": "",
        "prefix": "healthcheck_",
        "suffix": "_healthcheck",
        "connection": {
          "max_idle_connections": 10,
          "max_active_connections": 10,
          "connect_timeout": 500,
          "read_timeout": 500,
          "idle_keep_alive": 30,
          "max_keep_alive": 60,
          "wait_for_connection": false
        }
      },
      "log": {
        "enable": true,
        "level": "info",
        "target": "file",
        "format": "json",
        "path": "/tmp/healthcheck.log"
      }
    }
  },
  "error_log": {
      "enable": true,
      "level": "info",
      "target": "stdout",
      "format": "json",
      "path": "/tmp/healthcheck.log"
  }
}
~~~

## zone format in redis db

### keys

* redins:zones is a set containing all active zones
~~~
redis-cli>SMEMBERS redins:zones
1) "example.com."
2) "example.net."
~~~

* redins:zones:XXXX.XXX. is a hash map containing dns RRs, @ is used for TLD records.
~~~
redis-cli>HKEYS redins:zones:example.com.
1) "@"
2) "www"
3) "ns"
4) "subdomain.www"
~~~
@ is a special case used for root data

* redins:zones:XXXX.XXX.:config is a string containing zone specific configurations
~~~
redis-cli>GET redins:zones:example.com.:config
"{\"soa\":{\"ttl\":300, \"minttl\":100, \"mbox\":\"hostmaster.example.com.\",\"ns\":\"ns1.example.com.\",\"refresh\":44,\"retry\":55,\"expire\":66, \"serial\":23232}}"
~~~

* redins:zones:XXXX.XXX.:pub and redins:zones:XXXX.XXX.:priv contains keypair for dnssec 
~~~
redis-cli>GET redins:zones:XXXX.XXX.:pub
"dnssec_test.com. IN DNSKEY 256 3 5 AwEAAaKsF5vxBfKuqeUa4+ugW37ftFZOyo+k7r2aeJzZdIbYk//P/dpC HK4uYG8Z1dr/qeo12ECNVcf76j+XAdJD841ELiRVaZteH8TqfPQ+jdHz 10e8Sfkh7OZ4oBwSCXWj+Q=="
~~~

### zones

### dns RRs 

dns RRs are stored in redis as json strings inside a hash map using address as field key.
 there are two special labels: @config for zone specific configuration and @ for TLD records.

~~~
redis-cli>HGETALL example.com.
1) "@"
2) "@config"
3) "www"
~~~

#### A

~~~json
{
    "a":{
        "ttl" : 360,
        "records":[
          {
            "ip" : "1.2.3.4",
            "country" : "US",
            "asn": 444,
            "weight" : 10
          },
          {
            "ip" : "2.2.3.4",
            "country" : "US",
            "asn": 444,
            "weight" : 10
          }
        ],
        "filter": {
          "count":"single",
          "order": "rr",
          "geo_filter":"country"
        },
        "health_check":{
          "enable":true,
          "uri": "/hc/test.html",
          "port": 8080,
          "protocol": "https",
          "up_count":3,
          "down_count":-3,
          "timeout":1000
        }
    }
}
~~~

#### AAAA

~~~json
{
    "aaaa":{
        "ttl" : 360,
        "records":[
          {
            "ip" : "1.2.3.4",
            "country" : "US",
            "asn": 444,
            "weight" : 10
          },
          {
            "ip" : "1.2.3.4",
            "country" : "US",
            "asn": 444,
            "weight" : 10
          }
        ],
        "filter": {
          "count":"single",
          "order": "rr",
          "geo_filter":"country"
        },
        "health_check":{
          "enable":true,
          "uri": "/hc/test.html",
          "port": 8080,
          "protocol": "https",
          "up_count":3,
          "down_count":-3,
          "timeout":1000
        }
    }
}
~~~

`filter` : filtering mode:
* `count` : return single or multiple results. values : "multi", "single"
* `order` : order of result. values : "none" - saved order, "weighted" - weighted shuffle, "rr" - uniform shuffle
* `geo_filter` : geo filter. values : "country" - same country, "location" - nearest destination, "asn" - same isp, "asn+country" same isp then same country, "none"

`health_check` : health check configuration
* `enable` : enable/disable healthcheck for this host:ip
* `uri` : uri to use in healthcheck request
* `port` : port to use in healthcheck request
* `protocol` : protocol to use in healthcheck request, can be http or https
* `up_count` : number of successful healthcheck requests to consider an ip valid
* `down_count` : number of unsuccessful healthcheck requests to consider an ip invalid
* `timeout time` : to wait for a healthcheck response

#### ANAME

~~~json
{
    "aname":{
        "location": "x.example.com."
    }
}
~~~

#### CNAME

~~~json
{
    "cname":{
        "host" : "x.example.com.",
        "ttl" : 360
    }
}
~~~

#### TXT

~~~json
{
    "txt":{
      "ttl" : 360,
      "records":[
        {"text" : "this is a text"},
        {"text" : "this is another text"}
      ]
    }
}
~~~

#### NS

~~~json
{
    "ns":{
        "ttl" : 360,
        "records":[
          {"host" : "ns1.example.com."},
          {"host" : "ns2.example.com."}
        ]
    }
}
~~~

#### MX

~~~json
{
    "mx":{
        "ttl" : 360,
        "records":[
            {
              "host" : "mx1.example.com.",
              "preference" : 10
            },
            {
              "host" : "mx2.example.com.",
              "preference" : 20
            }
        ]
    }
}
~~~

#### SRV

~~~json
{
    "srv":{
      "ttl" : 360,
      "records":[
        {
          "target" : "sip.example.com.",
          "port" : 555,
          "priority" : 10,
          "weight" : 100
        }
      ]
    }
}
~~~

#### CAA

~~~json
{
  "caa":{
    "ttl": 360,
    "records":[
      {
        "tag": "issuewild;",
        "value": "godaddy.com",
        "flag": 0
      }
    ]
  }
}
~~~

#### PTR

~~~json
{
  "ptr":{
    "ttl": 300,
    "domain": "mail.example.com"
  }
}
~~~

#### TLSA

~~~json
{
  "tlsa":{
    "ttl": 300,
    "records":[
      {
        "usage": 1,
        "selector": 1,
        "matching_type": 1,
        "certificate": "1CFC98A706BCF3683015"
      }
    ]
  }
}
~~~

#### config

~~~json
{
    "soa":{
        "ttl" : 100,
        "mbox" : "hostmaster.example.com.",
        "ns" : "ns1.example.com.",
        "refresh" : 44,
        "retry" : 55,
        "expire" : 66,
        "serial" : 25245235
    },
    "cname_flattening": true,
    "dnssec": true,
    "domain_id": "123456789"
}
~~~

* `cname_flattening`: enable/disable cname flattening, default: false
* `dnssec`: enable/disable dnssec, default: false
* `domain_id`: unique domain id for logging, optional

### zone example

~~~
$ORIGIN example.net.
 example.net.                 300 IN  SOA   <SOA RDATA>
 example.net.                 300     NS    ns1.example.net.
 example.net.                 300     NS    ns2.example.net.
 *.example.net.               300     TXT   "this is a wildcard"
 *.example.net.               300     MX    10 host1.example.net.
 sub.*.example.net.           300     TXT   "this is not a wildcard"
 host1.example.net.           300     A     5.5.5.5
 _ssh.tcp.host1.example.net.  300     SRV   <SRV RDATA>
 _ssh.tcp.host2.example.net.  300     SRV   <SRV RDATA>
 subdel.example.net.          300     NS    ns1.subdel.example.net.
 subdel.example.net.          300     NS    ns2.subdel.example.net.
~~~

above zone data should be stored at redis as follow:

~~~
redis-cli> smembers redins:zones
 1) "example.net."
 
redis-cli> hgetall redins:zones:example.net.
 1) "_ssh._tcp.host1"
 2) "{\"srv\":{\"ttl\":300, \"records\":[{\"target\":\"tcp.example.com.\",\"port\":123,\"priority\":10,\"weight\":100}]}}"
 3) "*"
 4) "{\"txt\":{\"ttl\":300, \"records\":[{\"text\":\"this is a wildcard\"}]},\"mx\":{\"ttl\":300, \"records\":[{\"host\":\"host1.example.net.\",\"preference\": 10}]}}"
 5) "host1"
 6) "{\"a\":{\"ttl\":300, \"records\":[{\"ip\":\"5.5.5.5\"}]}}"
 7) "sub.*"
 8) "{\"txt\":{\"ttl\":300, \"records\":[{\"text\":\"this is not a wildcard\"}]}}"
 9) "_ssh._tcp.host2"
10) "{\"srv\":{\"ttl\":300, \"records\":[{\"target\":\"tcp.example.com.\",\"port\":123,\"priority\":10,\"weight\":100}]}}"
11) "subdel"
12) "{\"ns\":{\"ttl\":300, \"records\":[{\"host\":\"ns1.subdel.example.net.\"},{\"host\":\"ns2.subdel.example.net.\"}]}"

redis-cli> get redins:zones:example.net.:config
"{\"soa\":{\"ttl\":300, \"minttl\":100, \"mbox\":\"hostmaster.example.net.\",\"ns\":\"ns1.example.net.\",\"refresh\":44,\"retry\":55,\"expire\":66, \"serial\":32343},\"ns\":[{\"ttl\":300, \"host\":\"ns1.example.net.\"},{\"ttl\":300, \"host\":\"ns2.example.net.\"}]}"

~~~


# Netmap

Netmap is a tool to gather information for a given network and render
that on a Hilbert curve as a square image.

The currently sole information source is nmap. It's used to run discovery
and port scans and render the information. The following metrics are used to
determine the color of a pixel:

* for host discovery scans, the RTT
* for port scans, the number of open ports

## How to use

Usage:

```bash
go run . --help
Usage of netmap:
  -file string
        full path where the generated heatmap should be written to (.jpg or .png)
  -help
        boolean flag to print this help message
  -network string
        network to gather data and generate heatmap for in CIDR notation (e.g. 192.168.0.1/24) (default "10.0.1.0/24")
  -scantype string
        type of scan to launch: hostup, webports, defaultports, allports (default "hostup")
  -transparent
        boolean flag whether or not to generate a transparent image
```

The following runs a host discovery scan against the given network and
writes the rendered image out as a PNG.

```bash
go run . --file=/tmp/heatmap.png --network=10.0.0.0/16
```

The result may look like the following:

![netmap sample](images/sample.png "netmap sample")

The more "heated" a pixel is, the faster was its response time. The heat
gradient is currently set as follows (from cold to hot):

black - blue - cyan - green - yellow - red - white

## Licence (Apache 2)

```
Copyright 2016 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

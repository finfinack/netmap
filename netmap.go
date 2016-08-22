// Copyright 2016 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
The netmap binary renders an image with information gathered about a given network.

Notes:
- scans are done with aggressive (-T5 like) config with nmap without sudo privileges
- make sure you meet the following prerequisites: nmap is installed and findable in $PATH
*/
package main

import (
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"log"
	"math"
	"net"
	"os"
	"strings"

	"github.com/google/hilbert"
)

var (
	file        = flag.String("file", "", "full path where the generated heatmap should be written to (.jpg or .png)")
	network     = flag.String("network", "10.0.0.0/24", "network to gather data and generate heatmap for in CIDR notation (e.g. 192.168.1.0/24)")
	scantype    = flag.String("scantype", "hostup", "type of scan to launch: hostup, webports, defaultports, allports")
	transparent = flag.Bool("transparent", false, "boolean flag whether or not to generate a transparent image")
	help        = flag.Bool("help", false, "boolean flag to print this help message")

	// Colors defining the gradient in the heatmap. The higher the index, the warmer.
	colors = map[int]color.RGBA{
		0: color.RGBA{0, 0, 0, 255},       // black
		1: color.RGBA{0, 0, 255, 255},     // blue
		2: color.RGBA{0, 255, 255, 255},   // cyan
		3: color.RGBA{0, 255, 0, 255},     // green
		4: color.RGBA{255, 255, 0, 255},   // yellow
		5: color.RGBA{255, 0, 0, 255},     // red
		6: color.RGBA{255, 255, 255, 255}, // white
	}
)

// getColor determines the color of a pixel based on a color gradient and a pixel "level".
// http://www.andrewnoske.com/wiki/Code_-_heatmaps_and_color_gradients
func getColor(lvl uint16) color.RGBA {
	// Return early for the extremes.
	if lvl <= 0 {
		return colors[0]
	} else if lvl >= math.MaxUint16 {
		return colors[len(colors)-1]
	}
	// Find the first color in the gradient where the "level" is higher than the level we're looking for.
	// Then determine how far along we are between the previous and next color in the gradient and use that
	// to calculate the color between the two.
	for i := 0; i < len(colors); i++ {
		currC := colors[i]
		currV := uint16(i * math.MaxUint16 / len(colors))
		if lvl < currV {
			prevC := colors[int(math.Max(0.0, float64(i-1)))]
			diff := uint16(math.Max(0.0, float64(i-1)))*math.MaxUint16/uint16(len(colors)) - currV
			fract := 0.0
			if diff != 0 {
				fract = float64(lvl) - float64(currV)/float64(diff)
			}
			return color.RGBA{
				uint8(float64(prevC.R-currC.R)*fract + float64(currC.R)),
				uint8(float64(prevC.G-currC.G)*fract + float64(currC.G)),
				uint8(float64(prevC.B-currC.B)*fract + float64(currC.B)),
				uint8(float64(prevC.A-currC.A)*fract + float64(currC.A)),
			}
		}
	}
	return colors[len(colors)-1]
}

// IPv4ToInt calculates the corresponding uint32 for a given IPv4 address.
func IPv4ToInt(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3])
}

// getLength calculates the side length of the square image for a given network.
func getLength(n *net.IPNet) (int, error) {
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return 0, fmt.Errorf("the given network is not an IPv4 network: %v", n)
	}
	l := math.Sqrt(math.Pow(float64(2), float64(bits-ones)))
	if l != math.Ceil(l) {
		return 0, fmt.Errorf("please choose a network that allows a square image (e.g. /24, /16).")
	}
	return int(l), nil
}

// renderImage renders an image for a given network with a list of hosts.
func renderImage(n *net.IPNet, t bool, st ScanType, hosts []Host) (image.Image, error) {
	l, _ := getLength(n)
	canvas := image.NewRGBA(image.Rectangle{
		Min: image.Point{0, 0},
		Max: image.Point{l, l},
	})
	if !t {
		draw.Draw(canvas, canvas.Bounds(), &image.Uniform{colors[0]}, image.ZP, draw.Src)
	}

	hil, err := hilbert.New(int(l))
	if err != nil {
		return nil, fmt.Errorf("unable to create hilbert map for given network: %s", err)
	}

	startIP := IPv4ToInt(n.IP)
	max := 0
	switch st {
	case ScanHostUp:
		for _, h := range hosts {
			if h.RTT > max {
				max = h.RTT
			}
		}
	default:
		for _, h := range hosts {
			if len(h.OpenPorts) > max {
				max = len(h.OpenPorts)
			}
		}
	}

	for _, h := range hosts {
		t := IPv4ToInt(h.IP) - startIP
		x, y, err := hil.Map(int(t))
		if err != nil {
			continue
		}
		lvl := uint16(0)
		switch st {
		case ScanHostUp:
			lvl = uint16(h.RTT * int(math.MaxUint16) / max)
		default:
			lvl = uint16(len(h.OpenPorts) * int(math.MaxUint16) / max)
		}
		canvas.SetRGBA(x, y, getColor(lvl))
	}
	return canvas, nil
}

// writeImage writes a given image to the given path.
func writeImage(path string, canvas image.Image) error {
	f, _ := os.Create(*file)
	defer f.Close()

	switch {
	case strings.HasSuffix(path, ".png"):
		png.Encode(f, canvas)
	case strings.HasSuffix(path, ".jpg"):
		jpeg.Encode(f, canvas, &jpeg.Options{jpeg.DefaultQuality})
	}
	return nil
}

// printUsage prints the flags for the application and exits.
func printUsage(m string, fatal bool) {
	if m != "" {
		fmt.Printf("%s\n\n", m)
	}
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	if fatal {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}

func main() {
	flag.Parse()

	if *help {
		printUsage("", false)
	}

	// Check given parameters and prepare
	if *file == "" {
		printUsage("please specify a filename and path to store the heatmap.", true)
	}
	if !strings.HasSuffix(*file, ".jpg") && !strings.HasSuffix(*file, ".png") {
		printUsage("please use .jpg or .png files for the heatmap.", true)
	}
	_, n, err := net.ParseCIDR(*network)
	if err != nil {
		printUsage(fmt.Sprintf("the given network does not parse: %s", err), true)
	}

	scantype := ScanType(strings.ToUpper(*scantype))
	hosts, err := Scan(n, scantype)
	if err != nil {
		printUsage(fmt.Sprintf("scan failed: %s", err), true)
	}

	canvas, err := renderImage(n, *transparent, scantype, hosts)
	if err != nil {
		log.Fatalf("unable to render image: %s", err)
	}

	if err := writeImage(*file, canvas); err != nil {
		log.Fatalf("unable to write image: %s", canvas)
	}
}

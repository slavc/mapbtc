package main

import (
	"fmt"
	"os"
	"strings"
	"bufio"
	"io"
)

type PeerGraph struct {
	nodes []string // graph nodes
	edges []uint64 // bitmap representing the directed edges
	peers map[string]int // peer name (e.g. IP address) -> index in the nodes array
}
const bitsPerWord = 64

func LoadPeerGraph(path string) (*PeerGraph, error) {
	g := NewPeerGraph()

	err := g.loadNodes(path)
	if err != nil {
		return nil, err
	}

	g.resizeEdges()

	err = g.loadEdges(path)
	if err != nil {
		return nil, err
	}

	return g, nil
}

func NewPeerGraph() *PeerGraph {
	g := new(PeerGraph)
	g.nodes = make([]string, 0)
	g.edges = make([]uint64, 0)
	g.peers = make(map[string]int)
	return g
}

func (g *PeerGraph) loadNodes(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	rd := bufio.NewReader(f)

	lineNo := 0
	for {
		lineNo++
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if lineNo == 1 {
			// skip header
			continue
		}
		if len(line) == 0 {
			return fmt.Errorf("%s: line %d: empty line", path, lineNo)
		}
		line = line[:len(line)-1]
		fields := strings.Split(line, ",")
		if len(fields) != 2 {
			return fmt.Errorf("%s: line %d: %d fields instead of 2", path, lineNo, len(fields))
		}

		dstPeer := fields[0]
		srcPeer := fields[1]

		_, ok := g.peers[dstPeer]
		if !ok {
			g.nodes = append(g.nodes, dstPeer)
			g.peers[dstPeer] = len(g.nodes) - 1
		}

		_, ok = g.peers[srcPeer]
		if !ok {
			g.nodes = append(g.nodes, srcPeer)
			g.peers[srcPeer] = len(g.nodes) - 1
		}
	}

	return nil
}

func (g *PeerGraph) loadEdges(path string) error {
	if len(g.nodes) == 0 {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	rd := bufio.NewReader(f)

	g.resizeEdges()

	lineNo := 0
	for {
		lineNo++
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if len(line) == 0 {
			return fmt.Errorf("%s: line %d: empty line", path, lineNo)
		}
		line = line[:len(line)-1]
		if lineNo == 1 {
			// skip header
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) != 2 {
			return fmt.Errorf("%s: line %d: %d fields instead of 2", path, lineNo, len(fields))
		}

		dstPeer := fields[0]
		srcPeer := fields[1]

		dstIndex, ok := g.peers[dstPeer]
		if !ok {
			return fmt.Errorf("%s: line %d: peer %s is not present in the node array", path, lineNo, dstPeer)
		}
		srcIndex, ok := g.peers[srcPeer]
		if !ok {
			return fmt.Errorf("%s: line %d: peer %s is not present in the node array", path, lineNo, srcPeer)
		}

		g.setBit(srcIndex, dstIndex)
	}

	return nil
}

func (g *PeerGraph) resizeEdges() {
	numNodes := len(g.nodes)
	numBits := numNodes * numNodes // number of possible edges
	numWords := numBits / bitsPerWord
	if numNodes % bitsPerWord != 0 {
		numWords++
	}
	g.edges = make([]uint64, numWords)
}

func (g *PeerGraph) computeOffset(row int, col int) (uint, uint) {
	offset := uint(row * len(g.nodes) + col)
	wordOffset := offset / bitsPerWord
	bitOffset := offset % bitsPerWord
	return wordOffset, bitOffset
}

func (g *PeerGraph) setBit(row int, col int) {
	wordOffset, bitOffset := g.computeOffset(row, col)
	g.edges[wordOffset] |= uint64(1) << bitOffset
}

func (g *PeerGraph) testBit(row int, col int) bool {
	wordOffset, bitOffset := g.computeOffset(row, col)
	if (g.edges[wordOffset] & (uint64(1) << bitOffset)) != uint64(0) {
		return true
	}
	return false
}

func (g *PeerGraph) Save(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE | os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "DstNode,SrcNode\n")
	for row := 0; row < len(g.nodes); row++ {
		for col := 0; col < len(g.nodes); col++ {
			if g.testBit(row, col) {
				fmt.Fprintf(f, "%s,%s\n", g.nodes[col], g.nodes[row])
			}
		}
	}

	return nil
}

func (g *PeerGraph) PeerCount() int {
	return len(g.nodes)
}

func (g *PeerGraph) GetPeerName(i int) string {
	return g.nodes[i]
}

func (g *PeerGraph) GetEdgeCount(i int) (outgoing uint, incoming uint) {
	row := i
	for col := 0; col < len(g.nodes); col++ {
		if g.testBit(row, col) {
			outgoing++
		}
	}

	col := i
	for row := 0; row < len(g.nodes); row++ {
		if g.testBit(row, col) {
			incoming++
		}
	}

	return
}

func computeMostAndLeastConnectedPeers(g *PeerGraph) {
	type node struct {
		index int
		out uint // number of outgoing edges
		in uint // number of incoming edges
	}
	var least node
	var most node
	var cur node

	least.index = -1
	most.index = -1

	for cur.index = 0; cur.index < g.PeerCount(); cur.index++ {
		cur.out, cur.in = g.GetEdgeCount(cur.index)
		if least.index == -1 || least.out + least.in > cur.out + cur.in {
			least = cur
		}
		if most.index == -1 || most.out + most.in < cur.out + cur.in {
			most = cur
		}
	}

	fmt.Printf("Most connected peer: %v (%v out, %v in)\n", g.GetPeerName(most.index), most.out, most.in)
	fmt.Printf("Least connected peer: %v (%v out, %v in)\n", g.GetPeerName(least.index), least.out, least.in)
}

func main() {
	g, err := LoadPeerGraph("peer_graph.csv")
	if err != nil {
		fmt.Printf("error: failed to load peer graph: %v", err)
		os.Exit(1)
	}

	computeMostAndLeastConnectedPeers(g)
}

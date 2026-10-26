package core

// A compact, local symbol-based neural classifier. It learns from *explicitly*
// confirmed historical decisions; never from its own outputs or automatic
// reject/tag actions. This is an independent alpha model, not Rspamd KANN
// weights or a compatible replacement for the Rspamd neural wire format.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
)

const neuralFeatures = 128
const neuralHidden = 12
const neuralMaxSamples = 25000

type NeuralModel struct {
	W1      [neuralHidden][neuralFeatures]float64 `json:"w1"`
	B1      [neuralHidden]float64                 `json:"b1"`
	W2      [neuralHidden]float64                 `json:"w2"`
	B2      float64                               `json:"b2"`
	Ham     int                                   `json:"ham"`
	Spam    int                                   `json:"spam"`
	Samples map[string]string                     `json:"samples"`
}
type NeuralScore struct {
	Ham         int     `json:"ham"`
	Spam        int     `json:"spam"`
	Ready       bool    `json:"ready"`
	Probability float64 `json:"probability"`
	Features    int     `json:"features"`
}

func newNeural() NeuralModel {
	m := NeuralModel{Samples: map[string]string{}}
	for h := 0; h < neuralHidden; h++ {
		for j := 0; j < neuralFeatures; j++ {
			var input [4]byte
			binary.BigEndian.PutUint16(input[:2], uint16(h))
			binary.BigEndian.PutUint16(input[2:], uint16(j))
			sum := sha256.Sum256(append([]byte("SpamGate neural seed 1"), input[:]...))
			n := float64(binary.BigEndian.Uint32(sum[:4])) / float64(^uint32(0))
			m.W1[h][j] = (n - 0.5) * 0.12
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("SpamGate output seed %d", h)))
		n := float64(binary.BigEndian.Uint32(sum[:4])) / float64(^uint32(0))
		m.W2[h] = (n - 0.5) * 0.12
	}
	return m
}
func neuralInput(findings []Finding) ([]int, error) {
	seen := map[int]bool{}
	for _, f := range findings {
		if len(f.Symbol) > 128 || len(f.Symbol) == 0 || strings.HasPrefix(f.Symbol, "NEURAL_") || strings.HasPrefix(f.Symbol, "FUZZY_") || f.Symbol == "FORCED_ACTION" {
			continue
		}
		sum := sha256.Sum256([]byte(f.Symbol))
		seen[int(binary.BigEndian.Uint64(sum[:8])%neuralFeatures)] = true
	}
	if len(seen) == 0 {
		return nil, errors.New("message has no usable scoring signals for neural training")
	}
	indices := make([]int, 0, len(seen))
	for index := range seen {
		indices = append(indices, index)
	}
	return indices, nil
}
func neuralForward(m *NeuralModel, x []int) (float64, [neuralHidden]float64) {
	var hidden [neuralHidden]float64
	for h := 0; h < neuralHidden; h++ {
		z := m.B1[h]
		for _, j := range x {
			z += m.W1[h][j]
		}
		hidden[h] = math.Tanh(z)
	}
	z := m.B2
	for h := 0; h < neuralHidden; h++ {
		z += hidden[h] * m.W2[h]
	}
	if z > 30 {
		z = 30
	} else if z < -30 {
		z = -30
	}
	return 1 / (1 + math.Exp(-z)), hidden
}
func (s *Store) loadNeural() error {
	s.neural = newNeural()
	raw, err := os.ReadFile(filepath.Join(s.dir, "neural.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(raw) > 3<<20 {
		return errors.New("neural model is too large")
	}
	var m NeuralModel
	if err = json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("neural model: %w", err)
	}
	if m.Samples == nil || len(m.Samples) > neuralMaxSamples || m.Ham < 0 || m.Spam < 0 || m.Ham+m.Spam != len(m.Samples) {
		return errors.New("invalid neural training metadata")
	}
	for _, label := range m.Samples {
		if label != "spam" && label != "ham" {
			return errors.New("invalid neural label")
		}
	}
	for h := 0; h < neuralHidden; h++ {
		if math.IsNaN(m.W2[h]) || math.IsInf(m.W2[h], 0) || math.Abs(m.W2[h]) > 100 {
			return errors.New("invalid neural output weights")
		}
		if math.IsNaN(m.B1[h]) || math.IsInf(m.B1[h], 0) || math.Abs(m.B1[h]) > 100 {
			return errors.New("invalid neural hidden bias")
		}
		for _, w := range m.W1[h] {
			if math.IsNaN(w) || math.IsInf(w, 0) || math.Abs(w) > 100 {
				return errors.New("invalid neural input weights")
			}
		}
	}
	if math.IsNaN(m.B2) || math.IsInf(m.B2, 0) || math.Abs(m.B2) > 100 {
		return errors.New("invalid neural output bias")
	}
	s.neural = m
	return nil
}
func (s *Store) NeuralStats() NeuralScore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.neural
	return NeuralScore{Ham: m.Ham, Spam: m.Spam, Ready: m.Ham >= 10 && m.Spam >= 10}
}
func (s *Store) ScoreNeural(findings []Finding) NeuralScore {
	x, err := neuralInput(findings)
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.neural
	out := NeuralScore{Ham: m.Ham, Spam: m.Spam, Ready: m.Ham >= 10 && m.Spam >= 10}
	if err != nil || !out.Ready {
		return out
	}
	out.Features = len(x)
	out.Probability, _ = neuralForward(&m, x)
	return out
}
func (s *Store) TrainNeural(id, label string) (NeuralScore, error) {
	if label != "spam" && label != "ham" {
		return NeuralScore{}, errors.New("label must be spam or ham")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	message, ok := s.messages[id]
	if !ok {
		return NeuralScore{}, errors.New("message not found")
	}
	x, err := neuralInput(message.Findings)
	if err != nil {
		return NeuralScore{}, err
	}
	if existing, ok := s.neural.Samples[id]; ok {
		if existing != label {
			return NeuralScore{}, errors.New("already trained with another label; conflicting updates are prohibited")
		}
		return NeuralScore{Ham: s.neural.Ham, Spam: s.neural.Spam, Ready: s.neural.Ham >= 10 && s.neural.Spam >= 10}, nil
	}
	if len(s.neural.Samples) >= neuralMaxSamples {
		return NeuralScore{}, errors.New("neural training sample limit reached")
	}
	next := s.neural
	next.Samples = make(map[string]string, len(s.neural.Samples)+1)
	for k, v := range s.neural.Samples {
		next.Samples[k] = v
	}
	target := 0.0
	if label == "spam" {
		target = 1
		next.Spam++
	} else {
		next.Ham++
	}
	// Bounded SGD: manual learning only, tiny dense network, no GPU required.
	const rate = 0.12
	for epoch := 0; epoch < 12; epoch++ {
		y, hidden := neuralForward(&next, x)
		delta := y - target
		var outputWeights [neuralHidden]float64
		copy(outputWeights[:], next.W2[:])
		for h := 0; h < neuralHidden; h++ {
			next.W2[h] -= rate * delta * hidden[h]
		}
		next.B2 -= rate * delta
		for h := 0; h < neuralHidden; h++ {
			gradient := delta * outputWeights[h] * (1 - hidden[h]*hidden[h])
			next.B1[h] -= rate * gradient
			for _, j := range x {
				next.W1[h][j] -= rate * gradient
			}
		}
	}
	next.Samples[id] = label
	if err := atomicJSON(filepath.Join(s.dir, "neural.json"), next); err != nil {
		return NeuralScore{}, err
	}
	s.neural = next
	return NeuralScore{Ham: next.Ham, Spam: next.Spam, Ready: next.Ham >= 10 && next.Spam >= 10, Features: len(x)}, nil
}

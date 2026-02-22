package webrtc

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/stretchr/testify/require"
)

func TestWebRTCStateResume(t *testing.T) {
	logFactory := logging.NewDefaultLoggerFactory()
	logFactory.DefaultLogLevel = logging.LogLevelTrace

	s := SettingEngine{}
	s.DisableCloseByDTLS(true)
	s.LoggerFactory = logFactory
	api := NewAPI(WithSettingEngine(s))

	// 1. Establish a local PeerConnection pair using proven signalPair approach
	peerA, err := api.NewPeerConnection(Configuration{})
	require.NoError(t, err)

	peerB, err := api.NewPeerConnection(Configuration{})
	require.NoError(t, err)

	// Add audio tracks
	trackA, err := NewTrackLocalStaticSample(RTPCodecCapability{MimeType: MimeTypeOpus}, "audio_A", "pion_A")
	require.NoError(t, err)
	_, err = peerA.AddTrack(trackA)
	require.NoError(t, err)

	trackB, err := NewTrackLocalStaticSample(RTPCodecCapability{MimeType: MimeTypeOpus}, "audio_B", "pion_B")
	require.NoError(t, err)
	_, err = peerB.AddTrack(trackB)
	require.NoError(t, err)

	// State change logging
	peerA.OnConnectionStateChange(func(s PeerConnectionState) {
		t.Logf("PeerA State: %s", s)
	})
	peerB.OnConnectionStateChange(func(s PeerConnectionState) {
		t.Logf("PeerB State: %s", s)
	})

	// Use proven signalPair approach
	err = signalPairWithOptions(peerA, peerB, withDisableInitialDataChannel(true))
	require.NoError(t, err)

	// Wait for initial connection
	require.Eventually(t, func() bool {
		return peerA.ConnectionState() == PeerConnectionStateConnected &&
			peerB.ConnectionState() == PeerConnectionStateConnected
	}, 10*time.Second, 100*time.Millisecond)
	t.Log("Initial connection established")

	// 2. Export state from PeerA
	state, err := peerA.ExportConnectionState()
	require.NoError(t, err)
	require.NotEmpty(t, state)

	// Collect PeerB's local candidates (as ICE-level candidates) for later re-injection
	bAgent := peerB.iceTransport.gatherer.getAgent()
	require.NotNil(t, bAgent)
	peerBICECandidates, err := bAgent.GetLocalCandidates()
	require.NoError(t, err)
	t.Logf("PeerB ICE candidates for re-injection: %d", len(peerBICECandidates))
	for i, c := range peerBICECandidates {
		t.Logf("  PeerB cand[%d]: %s", i, c)
	}

	// 3. Tear down Peer A
	require.NoError(t, peerA.Close())
	time.Sleep(500 * time.Millisecond)

	// Invalidate PeerB's selected pair BEFORE clearing old remote candidates
	require.NoError(t, peerB.iceTransport.InvalidateSelectedPair())
	t.Log("PeerB selected pair invalidated")

	// 4. Create Peer A' and Resume
	peerAPrime, err := api.NewPeerConnection(Configuration{})
	require.NoError(t, err)

	peerAPrime.OnConnectionStateChange(func(s PeerConnectionState) {
		t.Logf("PeerAPrime State: %s", s)
	})

	// Collect PeerAPrime's new candidates and add them to PeerB's ICE agent directly
	var mu sync.Mutex
	var primeICECandidates []ice.Candidate
	peerAPrime.OnICECandidate(func(c *ICECandidate) {
		if c != nil {
			t.Logf("PeerAPrime candidate: %s", c.String())
			iceCand, err2 := c.ToICE()
			if err2 != nil {
				t.Logf("Failed to convert PeerAPrime candidate: %v", err2)
				return
			}
			mu.Lock()
			primeICECandidates = append(primeICECandidates, iceCand)
			mu.Unlock()
			// Add directly to PeerB's ICE agent
			if addErr := bAgent.AddRemoteCandidate(iceCand); addErr != nil {
				t.Logf("Failed to add PeerAPrime candidate to PeerB agent: %v", addErr)
			} else {
				t.Logf("Added PeerAPrime candidate to PeerB agent: %s", iceCand)
			}
		}
	})

	// Resume with exported state
	t.Log("Resuming connection...")
	err = peerAPrime.ResumeConnection(state)
	require.NoError(t, err)

	// Add PeerB's ICE candidates directly to PeerAPrime's ICE agent
	primeAgent := peerAPrime.iceTransport.gatherer.getAgent()
	require.NotNil(t, primeAgent)
	for _, c := range peerBICECandidates {
		if addErr := primeAgent.AddRemoteCandidate(c); addErr != nil {
			t.Logf("Failed to add PeerB candidate to PeerAPrime agent: %v", addErr)
		} else {
			t.Logf("Added PeerB candidate to PeerAPrime agent: %s", c)
		}
	}

	// Debug credentials
	localUfrag, localPwd, _ := primeAgent.GetLocalUserCredentials()
	remoteUfrag, remotePwd, _ := primeAgent.GetRemoteUserCredentials()
	t.Logf("PeerAPrime creds: local=%s/%s remote=%s/%s", localUfrag, localPwd, remoteUfrag, remotePwd)
	bLocalUfrag, bLocalPwd, _ := bAgent.GetLocalUserCredentials()
	bRemoteUfrag, bRemotePwd, _ := bAgent.GetRemoteUserCredentials()
	t.Logf("PeerB creds: local=%s/%s remote=%s/%s", bLocalUfrag, bLocalPwd, bRemoteUfrag, bRemotePwd)

	// Wait for PeerAPrime to connect, dump goroutines on failure
	connected := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if peerAPrime.ConnectionState() == PeerConnectionStateConnected {
			connected = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !connected {
		buf := make([]byte, 1024*1024)
		n := runtime.Stack(buf, true)
		t.Logf("GOROUTINE DUMP (all goroutines):\n%s", buf[:n])
		t.Fatal("PeerAPrime never reached connected state")
	}

	t.Log("PeerAPrime successfully resumed and connected!")

	// Cleanup
	require.NoError(t, peerAPrime.Close())
	require.NoError(t, peerB.Close())
}

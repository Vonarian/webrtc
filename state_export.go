//go:build !js
// +build !js

package webrtc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pion/dtls/v3"
)

// ExportConnectionState gathers the underlying ICE, DTLS, and SRTP state
// to serialize and store in Redis.
func (pc *PeerConnection) ExportConnectionState() ([]byte, error) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	if pc.isClosed.Load() {
		return nil, errors.New("cannot export state from closed peerconnection")
	}

	state := map[string]interface{}{}

	// Get ICE Agent state
	if pc.iceTransport != nil && pc.iceTransport.gatherer != nil {
		agent := pc.iceTransport.gatherer.agent
		if agent != nil {
			selectedPair := agent.GetSelectedPair()
			if selectedPair != nil {
				state["ice_selected_local"] = selectedPair.Local.String()
				state["ice_selected_remote"] = selectedPair.Remote.String()
			}

			// Extract ICE parameters
			if localParams, err := pc.iceTransport.gatherer.GetLocalParameters(); err == nil {
				state["ice_local_parameters"] = localParams
			}
			if remoteParams, err := pc.iceTransport.GetRemoteParameters(); err == nil {
				state["ice_remote_parameters"] = remoteParams
			}
			state["ice_role"] = pc.iceTransport.Role()
		}
	}

	// Get DTLS state
	if pc.dtlsTransport != nil {
		if localParams, err := pc.dtlsTransport.GetLocalParameters(); err == nil {
			state["dtls_local_parameters"] = localParams
		}
		state["dtls_remote_parameters"] = pc.dtlsTransport.remoteParameters

		if pc.dtlsTransport.conn != nil {
			if dtlsState, ok := pc.dtlsTransport.conn.ConnectionState(); ok {
				dtlsBytes, err := dtlsState.MarshalBinary()
				if err == nil {
					state["dtls_state"] = dtlsBytes
				}
			}
		}
	}

	// Get SRTP state
	if pc.dtlsTransport != nil {
		srtpSession, _ := pc.dtlsTransport.getSRTPSession()
		srtcpSession, _ := pc.dtlsTransport.getSRTCPSession()

		if srtpSession != nil {
			localCtx := srtpSession.LocalContext()
			remoteCtx := srtpSession.RemoteContext()

			if localCtx != nil {
				localMap := make(map[uint32]uint64)
				for _, ssrc := range localCtx.GetActiveSRTPSSRCs() {
					if idx, ok := localCtx.GetSRTPSSRCIndex(ssrc); ok {
						localMap[ssrc] = idx
					}
				}
				state["srtp_local_ssrcs"] = localMap
			}

			if remoteCtx != nil {
				remoteMap := make(map[uint32]uint64)
				for _, ssrc := range remoteCtx.GetActiveSRTPSSRCs() {
					if idx, ok := remoteCtx.GetSRTPSSRCIndex(ssrc); ok {
						remoteMap[ssrc] = idx
					}
				}
				state["srtp_remote_ssrcs"] = remoteMap
			}
		}

		if srtcpSession != nil {
			localCtx := srtcpSession.LocalContext()
			remoteCtx := srtcpSession.RemoteContext()

			if localCtx != nil {
				localMap := make(map[uint32]uint32)
				for _, ssrc := range localCtx.GetActiveSRTCPSSRCs() {
					if idx, ok := localCtx.GetSRTCPSSRCIndex(ssrc); ok {
						localMap[ssrc] = idx
					}
				}
				state["srtcp_local_ssrcs"] = localMap
			}

			if remoteCtx != nil {
				remoteMap := make(map[uint32]uint32)
				for _, ssrc := range remoteCtx.GetActiveSRTCPSSRCs() {
					if idx, ok := remoteCtx.GetSRTCPSSRCIndex(ssrc); ok {
						remoteMap[ssrc] = idx
					}
				}
				state["srtcp_remote_ssrcs"] = remoteMap
			}
		}
	}

	return json.Marshal(state)
}

// ResumeConnection reconstructs a PeerConnection exactly from the given serialized state blob.
func (pc *PeerConnection) ResumeConnection(state []byte) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	var stateMap map[string]interface{}
	if err := json.Unmarshal(state, &stateMap); err != nil {
		return err
	}

	// 1. Resume ICE Agent
	if localParamsRaw, ok := stateMap["ice_local_parameters"].(map[string]interface{}); ok {
		var localParams ICEParameters
		b, _ := json.Marshal(localParamsRaw)
		_ = json.Unmarshal(b, &localParams)
		if pc.iceGatherer != nil {
			pc.iceGatherer.InjectLocalParameters(localParams)
		}
	}

	if pc.iceTransport != nil {
		if remoteParamsRaw, ok := stateMap["ice_remote_parameters"].(map[string]interface{}); ok {
			var remoteParams ICEParameters
			b, _ := json.Marshal(remoteParamsRaw)
			_ = json.Unmarshal(b, &remoteParams)

			var role ICERole
			if roleStr, ok := stateMap["ice_role"].(string); ok {
				role = newICERole(roleStr)
			} else if roleFloat, ok := stateMap["ice_role"].(float64); ok {
				role = ICERole(roleFloat)
			} else {
				role = ICERoleControlled
			}

			// This forces the creation of the agent with our injected credentials
			// and starts connectivity checks with the remote parameters without blocking
			if err := pc.iceTransport.Resume(pc.iceGatherer, remoteParams, &role); err != nil {
				pc.log.Errorf("Failed to resume ICE transport during resume: %v", err)
			}

			// Start gathering candidates automatically
			if err := pc.iceGatherer.Gather(); err != nil {
				pc.log.Errorf("Failed to start ICE gathering during resume: %v", err)
			}
		}
	}

	// 2. Resume DTLS
	if dtlsBytes, ok := stateMap["dtls_state"].(string); ok { // JSON serializes []byte as base64 string
		if pc.dtlsTransport != nil {
			rawBytes, _ := base64.StdEncoding.DecodeString(dtlsBytes)
			dtlsState := &dtls.State{}
			if err := dtlsState.UnmarshalBinary(rawBytes); err == nil {
				var remoteParams DTLSParameters
				if rpRaw, ok := stateMap["dtls_remote_parameters"].(map[string]interface{}); ok {
					b, _ := json.Marshal(rpRaw)
					_ = json.Unmarshal(b, &remoteParams)
				}

				if err := pc.dtlsTransport.Resume(dtlsState, remoteParams); err != nil {
					pc.log.Errorf("Failed to resume dtls transport: %v", err)
				}
			}
		}
	}

	// 3. Resume SRTP
	if pc.dtlsTransport != nil {
		srtpSession, _ := pc.dtlsTransport.getSRTPSession()
		srtcpSession, _ := pc.dtlsTransport.getSRTCPSession()

		if srtpSession != nil {
			if localCtx := srtpSession.LocalContext(); localCtx != nil {
				if localMapRaw, ok := stateMap["srtp_local_ssrcs"].(map[string]interface{}); ok {
					for ssrcStr, indexRaw := range localMapRaw {
						var ssrc uint32
						fmt.Sscanf(ssrcStr, "%d", &ssrc)
						if index, ok := indexRaw.(float64); ok {
							localCtx.InjectSRTPSSRCIndex(ssrc, uint64(index))
						}
					}
				}
			}
			if remoteCtx := srtpSession.RemoteContext(); remoteCtx != nil {
				if remoteMapRaw, ok := stateMap["srtp_remote_ssrcs"].(map[string]interface{}); ok {
					for ssrcStr, indexRaw := range remoteMapRaw {
						var ssrc uint32
						fmt.Sscanf(ssrcStr, "%d", &ssrc)
						if index, ok := indexRaw.(float64); ok {
							remoteCtx.InjectSRTPSSRCIndex(ssrc, uint64(index))
						}
					}
				}
			}
		}

		if srtcpSession != nil {
			if localCtx := srtcpSession.LocalContext(); localCtx != nil {
				if localMapRaw, ok := stateMap["srtcp_local_ssrcs"].(map[string]interface{}); ok {
					for ssrcStr, indexRaw := range localMapRaw {
						var ssrc uint32
						fmt.Sscanf(ssrcStr, "%d", &ssrc)
						if index, ok := indexRaw.(float64); ok {
							localCtx.InjectSRTCPSSRCIndex(ssrc, uint32(index))
						}
					}
				}
			}
			if remoteCtx := srtcpSession.RemoteContext(); remoteCtx != nil {
				if remoteMapRaw, ok := stateMap["srtcp_remote_ssrcs"].(map[string]interface{}); ok {
					for ssrcStr, indexRaw := range remoteMapRaw {
						var ssrc uint32
						fmt.Sscanf(ssrcStr, "%d", &ssrc)
						if index, ok := indexRaw.(float64); ok {
							remoteCtx.InjectSRTCPSSRCIndex(ssrc, uint32(index))
						}
					}
				}
			}
		}
	}

	return nil
}

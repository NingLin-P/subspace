window.SIDEBAR_ITEMS = {"enum":[["CircuitRelayClientError",""],["CreationError","Errors that might happen during network creation."],["GetClosestPeersError",""],["NetworkParametersPersistenceError",""],["PeerSyncStatus","Defines peer synchronization status."],["RelayMode","Defines relay configuration for the Node"],["RootBlockRequest","Root block by segment indexes protocol request."],["SendRequestError",""],["SubscribeError",""]],"fn":[["create","Create a new network node and node runner instances."],["peer_id","Converts public key from keypair to PeerId. It serves as the shared PeerId generating algorithm."],["start_prometheus_metrics_server","Start prometheus metrics server on the provided address."]],"mod":[["utils",""]],"struct":[["BootstrappedNetworkingParameters","Networking manager implementation with bootstrapped addresses. All other operations muted."],["Config","[`Node`] configuration."],["GenericRequestHandler",""],["MemoryProviderStorage","Memory based provider records storage."],["NetworkingParametersManager","Handles networking parameters. It manages network parameters set and its persistence."],["Node","Implementation of a network node on Subspace Network."],["NodeRunner","Runner for the Node."],["ObjectMappingsRequest","Object-mapping protocol request."],["ObjectMappingsResponse","Object-mapping protocol request."],["ParityDbProviderStorage","Defines provider record storage with DB persistence"],["PeerInfo","Defines peer current state."],["PeerInfoRequest","Peer-info protocol request."],["PeerInfoResponse","Peer-info protocol response."],["PieceByHashRequest","Piece-by-hash protocol request."],["PieceByHashResponse","Piece-by-hash protocol response."],["PiecesByRangeRequest","Pieces-by-range protocol request. Assumes requests with paging."],["PiecesByRangeResponse","Pieces-by-range protocol response. Assumes requests with paging."],["PiecesToPlot","Collection of pieces that potentially need to be plotted"],["RootBlockResponse","Root block by segment indexes protocol response."],["TopicSubscription","Topic subscription, will unsubscribe when last instance is dropped for a particular topic."],["UniqueRecordBinaryHeap","Limited-size max binary heap for Kademlia records’ keys."]],"trait":[["GenericRequest","Generic request with associated response"],["ProviderStorage",""]],"type":[["ObjectMappingsRequestHandler","Create a new object-mappings request handler."],["ParityDbError",""],["PeerInfoRequestHandler","Create a new peer-info request handler."],["PieceByHashRequestHandler","Create a new piece-by-hash request handler."],["PiecesByRangeRequestHandler","Create a new pieces-by-range request handler."],["RootBlockBySegmentIndexesRequestHandler","Create a new root-block-by-segment-indexes request handler."]]};
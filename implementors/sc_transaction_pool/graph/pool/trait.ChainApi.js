(function() {var implementors = {
"subspace_service":[["impl&lt;Client, Block, DomainHeader&gt; ChainApi for <a class=\"struct\" href=\"subspace_service/transaction_pool/struct.FullChainApiWrapper.html\" title=\"struct subspace_service::transaction_pool::FullChainApiWrapper\">FullChainApiWrapper</a>&lt;Client, Block, DomainHeader&gt;<span class=\"where fmt-newline\">where\n    Block: BlockT,\n    &lt;&lt;&lt;Block as BlockT&gt;::Header as HeaderT&gt;::Number as <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryInto.html\" title=\"trait core::convert::TryInto\">TryInto</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>&gt;&gt;::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryInto.html#associatedtype.Error\" title=\"type core::convert::TryInto::Error\">Error</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>,\n    Client: ProvideRuntimeApi&lt;Block&gt; + AuxStore + BlockBackend&lt;Block&gt; + BlockIdTo&lt;Block&gt; + HeaderBackend&lt;Block&gt; + HeaderMetadata&lt;Block, Error = Error&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + 'static,\n    DomainHeader: HeaderT,\n    Client::Api: TaggedTransactionQueue&lt;Block&gt; + SubspaceApi&lt;Block, FarmerPublicKey&gt; + DomainsApi&lt;Block, DomainHeader&gt;,</span>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()
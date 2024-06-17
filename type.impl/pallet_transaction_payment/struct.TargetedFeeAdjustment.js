(function() {var type_impls = {
"subspace_runtime_primitives":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Convert%3CFixedU128,+FixedU128%3E-for-TargetedFeeAdjustment%3CT,+S,+V,+M,+X%3E\" class=\"impl\"><a href=\"#impl-Convert%3CFixedU128,+FixedU128%3E-for-TargetedFeeAdjustment%3CT,+S,+V,+M,+X%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T, S, V, M, X&gt; Convert&lt;FixedU128, FixedU128&gt; for TargetedFeeAdjustment&lt;T, S, V, M, X&gt;<div class=\"where\">where\n    T: Config,\n    S: Get&lt;Perquintill&gt;,\n    V: Get&lt;FixedU128&gt;,\n    M: Get&lt;FixedU128&gt;,\n    X: Get&lt;FixedU128&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.convert\" class=\"method trait-impl\"><a href=\"#method.convert\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">convert</a>(previous: FixedU128) -&gt; FixedU128</h4></section></summary><div class='docblock'>Make conversion.</div></details></div></details>","Convert<FixedU128, FixedU128>","subspace_runtime_primitives::SlowAdjustingFeeUpdate"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-MultiplierUpdate-for-TargetedFeeAdjustment%3CT,+S,+V,+M,+X%3E\" class=\"impl\"><a href=\"#impl-MultiplierUpdate-for-TargetedFeeAdjustment%3CT,+S,+V,+M,+X%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T, S, V, M, X&gt; MultiplierUpdate for TargetedFeeAdjustment&lt;T, S, V, M, X&gt;<div class=\"where\">where\n    T: Config,\n    S: Get&lt;Perquintill&gt;,\n    V: Get&lt;FixedU128&gt;,\n    M: Get&lt;FixedU128&gt;,\n    X: Get&lt;FixedU128&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.min\" class=\"method trait-impl\"><a href=\"#method.min\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">min</a>() -&gt; FixedU128</h4></section></summary><div class='docblock'>Minimum multiplier. Any outcome of the <code>convert</code> function should be at least this.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.max\" class=\"method trait-impl\"><a href=\"#method.max\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">max</a>() -&gt; FixedU128</h4></section></summary><div class='docblock'>Maximum multiplier. Any outcome of the <code>convert</code> function should be less or equal this.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.target\" class=\"method trait-impl\"><a href=\"#method.target\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">target</a>() -&gt; Perquintill</h4></section></summary><div class='docblock'>Target block saturation level</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.variability\" class=\"method trait-impl\"><a href=\"#method.variability\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">variability</a>() -&gt; FixedU128</h4></section></summary><div class='docblock'>Variability factor</div></details></div></details>","MultiplierUpdate","subspace_runtime_primitives::SlowAdjustingFeeUpdate"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()
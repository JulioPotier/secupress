<?php
/**
 * Module Name: Always display all plugins
 * Description: Display all plugins that have been hidden and highlight them inthe plugins list
 * Main Module: plugins_themes
 * Author: SecuPress
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

add_action( 'admin_head-plugins.php', 'secupress_plugin_show_all_force_all_plugins_view_pre_current_active_plugins' );
add_filter( 'views_plugins', 'secupress_plugin_show_all_force_all_plugins_view_pre_current_active_plugins' );
function secupress_plugin_show_all_force_all_plugins_view_pre_current_active_plugins( $dummy ) {
	global $wp_list_table;

	$pre_current_active_plugins[] = $wp_list_table->items;
	if ( ! isset( $pre_current_active_plugins[1] ) ) {
		return $dummy;
	}
	$backgroundColor          = secupress_get_module_option( 'plugins_show-all-color', '#FAC898', 'plugins-themes' );
	$legend                   =  ' <span style="font-size:large;color:' . esc_attr( $backgroundColor ) .'">&#x25A0;</span>';
	$removed_plugins          = array_diff_key( $pre_current_active_plugins[0], $pre_current_active_plugins[1] );
	foreach( $removed_plugins as $slug => $data ) {
		$css = "<style type='text/css'>
			.plugins tr[data-plugin='$slug'], .plugins tr[data-plugin='$slug'] * {
			background: $backgroundColor !important;
			background-color: $backgroundColor !important;
		}</style>";
		// We add the CSS in the notice so if the notice is dismissed, the CSS rules will be too.
		secupress_cache_data( 'plugins_show-all-notice', 'plugins_list' );
		secupress_add_notice( sprintf( __( 'The plugin %s has been hidden ! (using the WP Filter %s)', 'secupress' ), secupress_code_me( $slug ), secupress_code_me( 'plugins_list' ) ) . $legend . $css, 'error', 'plugins_list-tab-' . md5( $css ) );
	}
	$wp_list_table->items = get_plugins();
}

add_action( 'load-plugins.php', 'secupress_plugin_show_all_force_all_plugins_view', SECUPRESS_INT_MAX );
/**
 * Force the plugins page to show all plugins
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @return (int|null) $value
 **/
function secupress_plugin_show_all_force_all_plugins_view() {
	$backgroundColor           = secupress_get_module_option( 'plugins_show-all-color', '#FAC898', 'plugins-themes' );
	$legend                    =  ' <span style="font-size:large;color:' . esc_attr( $backgroundColor ) .'">&#x25A0;</span>';
	// Handle the mustuse and dropin tabs
	$muse_visible_filtered     = apply_filters( 'show_advanced_plugins', true, 'mustuse' );
	$dins_visible_filtered     = apply_filters( 'show_advanced_plugins', true, 'dropins' );
	remove_all_filters( 'show_advanced_plugins' );
	add_filter( 'show_advanced_plugins', '__return_true' );
	$muse_visible_non_filtered = apply_filters( 'show_advanced_plugins', true, 'mustuse' );
	$dins_visible_non_filtered = apply_filters( 'show_advanced_plugins', true, 'dropins' );
	if ( $muse_visible_filtered !== $muse_visible_non_filtered ) {
        $css  = "<style type='text/css'>
            .mustuse {
                display: inline-block;
                background-color: $backgroundColor !important;
                border: 1px solid " . esc_js( secupress_darken_color( $backgroundColor, 75 ) ) . " !important;
            }
            .mustuse, .mustuse a, .mustuse span {
                color: " . esc_js( secupress_darken_color( $backgroundColor, 40 ) ) . " !important;
            }</style>";
        secupress_cache_data( 'plugins_show-all-notice', 'show_advanced_plugins' );
		secupress_add_notice( sprintf( __( 'The <strong>Must-Use</strong> tab has been hidden! (using the WP Filter %s)', 'secupress' ), secupress_code_me( 'show_advanced_plugins' ) ) . $legend . $css, 'error', 'mustuse-tab' );
	}

	if ( $dins_visible_filtered !== $dins_visible_non_filtered ) {
        $css  = "<style type='text/css'>
            .dropins {
                display: inline-block;
                background-color: $backgroundColor !important;
                border: 1px solid " . esc_js( secupress_darken_color( $backgroundColor, 75 ) ) . " !important;
            }
            .dropins, .dropins a, .dropins span {
                color: " . esc_js( secupress_darken_color( $backgroundColor, 40 ) ) . " !important;
            }</style>";
        secupress_cache_data( 'plugins_show-all-notice', 'show_advanced_plugins' );
		secupress_add_notice( sprintf( __( 'The <strong>Drop-in</strong> tab has been hidden! (using the WP Filter %s)', 'secupress' ), secupress_code_me( 'show_advanced_plugins' ) ) . $legend . $css, 'error', 'dropin-tab' );
	}

	// Handle the "all_plugins" filter
	$all_plugins_filtered     = array_keys( apply_filters( 'all_plugins', get_plugins() ) );
	remove_all_filters( 'all_plugins' );
	$all_plugins_non_filtered = array_keys( apply_filters( 'all_plugins', get_plugins() ) );
	$removed_plugins          = array_diff( $all_plugins_non_filtered, $all_plugins_filtered );
	foreach( $removed_plugins as $slug ) {
		$css = "<style type='text/css'>
			[data-plugin='$slug'] * {
			background-color: $backgroundColor !important;
		}</style>";
		secupress_cache_data( 'plugins_show-all-notice', 'all_plugins' );
		secupress_add_notice( sprintf( __( 'The plugin %s has been hidden ! (using the WP Filter %s)', 'secupress' ), secupress_code_me( $slug ), secupress_code_me( 'all_plugins' ) ) . $legend . $css, 'error', 'all_plugins-tab-' . md5( $css ) );
	}
	// Handle the "plugins_list" filter
	$all_plugins_filtered     = array_keys( apply_filters( 'plugins_list', ['mustuse'=>get_mu_plugins()] )['mustuse'] );
	remove_all_filters( 'plugins_list' );
	$all_plugins_non_filtered = array_keys( apply_filters( 'plugins_list', ['mustuse'=>get_mu_plugins()] )['mustuse'] );
	if ( function_exists( 'secupress_no_plugin_filter_plugins_list' ) ) {
		add_filter( 'plugins_list', 'secupress_no_plugin_filter_plugins_list' );
	}
	$removed_plugins          = array_diff( $all_plugins_non_filtered, $all_plugins_filtered );
	foreach( $removed_plugins as $slug ) {
		$css = "<style type='text/css'>
			.plugins tr[data-plugin='$slug'], .plugins tr[data-plugin='$slug'] * {
			background: $backgroundColor !important;
			background-color: $backgroundColor !important;
		}</style>";
		// We add the CSS in the notice so if the notice is dismissed, the CSS rules will be too.
		secupress_cache_data( 'plugins_show-all-notice', 'plugins_list' );
		secupress_add_notice( sprintf( __( 'The must-use plugin %s has been hidden ! (using the WP Filter %s)', 'secupress' ), secupress_code_me( $slug ), secupress_code_me( 'plugins_list' ) ) . $legend . $css, 'error', 'plugins_list-tab-' . md5( $css ) );
	}

	add_filter( 'get_user_metadata', 'secupress_dfp_force_all_plugins_view_meta', 10, 3 );
	function secupress_dfp_force_all_plugins_view_meta( $value, $object_id, $meta_key ) {
		if ( 'plugins_per_page' === $meta_key ) {
			return 999; // This the max allowed in the UI, set it to more will prevent the screenhelp form to be blocked, so don't.
		}
		return $value;
	}
}


add_action( 'admin_print_footer_scripts-plugins.php', 'secupress_plugin_show_all_hack_css', SECUPRESS_INT_MAX );
/**
 * Handle the CSS case when a plugin use CSS to display:none
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 **/
function secupress_plugin_show_all_hack_css() {
	$backgroundColor         = secupress_get_module_option( 'plugins_show-all-color', '#FAC898', 'plugins-themes' );
	?>
<script>
(function() {
	function secupressFakePluginsCSSHide() {
		const hiddenElements = Array.from(document.querySelectorAll('[data-plugin]:not(.plugin-update-tr)'))
			.filter(element => {
				const style  = window.getComputedStyle(element);
				return style.display === 'none';
			});
		hiddenElements.forEach(element => {

			const slug                    = element.getAttribute('data-plugin');
			element.style.display         = 'table-row';
			element.style.backgroundColor = '<?php echo esc_js( $backgroundColor ); ?>';

			const sibling = document.querySelector(`.plugin-update-tr[data-plugin="${slug}"]`);
			if (sibling) {
				sibling.style.display         = 'table-row';
				sibling.style.backgroundColor = element.style.backgroundColor;
			}
			var existingNotice = document.querySelector('[data-id="plugins_all_js_css"]');
			if (existingNotice) {
				existingNotice.innerHTML += '<p>' + "<?php echo esc_js( __( 'The plugin %s has been hidden! (using CSS)', 'secupress' ) ); ?>".replace('%s', '<code>'+slug+'</code>') + ' <span style="font-size:large;color:<?php echo esc_js( $backgroundColor ); ?>">&#x25A0;</span></p>';
			}
		});
	}
	secupressFakePluginsCSSHide();
})();
</script>
<?php
}

add_action( 'admin_footer', 'secupress_plugin_show_all_maybe_add_notice', 1 );
/**
 * Add an empty notice if need by CSS and JS hidden plugins since they cannot add it.
 *
 * @since 2.2.6
 * @author Julio Potier
 **/
function secupress_plugin_show_all_maybe_add_notice() {
	global $pagenow;
	// Can only works on plugins page, where the JS and CSS are triggered.
	if ( 'plugins.php' !== $pagenow ) {
		return;
	}
	$type = secupress_cache_data( 'plugins_show-all-notice' );
	if ( ! $type ) {
		secupress_add_notice( ' ', 'error', 'plugins_all_js_css' );
	}
}

add_action( 'admin_print_footer_scripts-plugins.php', 'secupress_plugin_show_all_hack_js', 1 );
/**
 * Handle the JS case when a plugin use JS to .remove()
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 **/
function secupress_plugin_show_all_hack_js() {
	$backgroundColor                           = secupress_get_module_option( 'plugins_show-all-color', '#FAC898', 'plugins-themes' );
	?>
<script>
(function() {
	function secupressFakePluginsJqueryRemove(event) {
		const slug                         = event.target.getAttribute("data-plugin");
		event.target.style.backgroundColor = '<?php echo esc_js( $backgroundColor ); ?>';

		const sibling = document.querySelector(`.plugin-update-tr[data-plugin="${slug}"]`);
		if (sibling) {
			sibling.style.display          = 'table-row';
			sibling.style.backgroundColor  = element.style.backgroundColor;
		}

		var childrenThTd                   = event.target.querySelectorAll('th, td');
		childrenThTd.forEach(function(child) {
			child.style.backgroundColor    = event.target.style.backgroundColor;
		});
		var existingNotice                     = document.querySelector('[data-id="plugins_all_js_css"]');
		if (existingNotice) {
			existingNotice.innerHTML          += '<br class="separator">' + "<?php echo esc_js( __( 'The plugin %s has been hidden! (using JS)', 'secupress' ) ); ?>".replace('%s', '<code>'+slug+'</code>') + ' <span style="font-size:large;color:<?php echo esc_js( $backgroundColor ); ?>">&#x25A0;</span>';
		}

		parentElement = document.getElementById('the-list');
		parentElement.insertBefore(event.target, parentElement.firstChild);
	}

	const observer = new MutationObserver((mutationsList) => {
		for (const mutation of mutationsList) {
			if (mutation.type === "childList") {
				for (const removedNode of mutation.removedNodes) {
					if (removedNode instanceof HTMLElement && removedNode.tagName === "TR" && removedNode.hasAttribute("data-plugin")) {
						secupressFakePluginsJqueryRemove({
							target: removedNode
						});
					}
				}
			}
		}
	});

	const config = {
		childList: true,
		subtree: true
	};

	observer.observe(document, config);
})();
</script>
	<?php
}
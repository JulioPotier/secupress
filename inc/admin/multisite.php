<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* !MULTISITE SETTINGS API ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

add_filter( 'secupress_whitelist_site_options', 'secupress_site_option_update_filter' );

/**
 * {@internal Missing Short Description}}
 *
 * @since 1.0
 *
 * @param (array) $options
 * @return (array)
 */
function secupress_site_option_update_filter( $options ) {
	$whitelist = secupress_cache_data( 'new_whitelist_site_options' );

	if ( is_array( $whitelist ) ) {
		$options = add_option_whitelist( $whitelist, $options );
	}

	return $options;
}


/*------------------------------------------------------------------------------------------------*/
/* !SAVE SETTINGS ON FORM SUBMIT ================================================================ */
/*------------------------------------------------------------------------------------------------*/

// !options.php do not handle site options. Let's use admin-post.php for multisite installations.

add_action( 'admin_post_update', 'secupress_update_site_option_on_submit' );

function secupress_update_site_option_on_submit() {
	$option_groups = array( 'secupress_global_settings' => 1 );
	$modules       = secupress_get_modules();

	foreach ( $modules as $module => $atts ) {
		$option_groups["secupress_{$module}_settings"] = 1;
	}

	if ( ! isset( $_POST['option_page'], $option_groups[ $_POST['option_page'] ] ) ) {
		return;
	}

	$option_group = $_POST['option_page'];

	if ( ! current_user_can( secupress_get_capability() ) ) {
		wp_die( __( 'Cheatin&#8217; uh?' ), 403 );
	}

	check_admin_referer( $option_group . '-options' );

	$whitelist_options = apply_filters( 'secupress_whitelist_site_options', array() );

	if ( ! isset( $whitelist_options[ $option_group ] ) ) {
		wp_die( __( '<strong>ERROR</strong>: options page not found.' ) );
	}

	$options = $whitelist_options[ $option_group ];

	if ( $options ) {

		foreach ( $options as $option ) {
			$option = trim( $option );
			$value  = null;

			if ( isset( $_POST[ $option ] ) ) {
				$value = $_POST[ $option ];
				if ( ! is_array( $value ) ) {
					$value = trim( $value );
				}
				$value = wp_unslash( $value );
			}

			update_site_option( $option, $value );
		}

	}

	/**
	 * Handle settings errors and return to options page
	 */
	// If no settings errors were registered add a general 'updated' message.
	if ( ! count( get_settings_errors() ) ) {
		add_settings_error( 'general', 'settings_updated', __( 'Settings saved.' ), 'updated' );
	}
	set_transient( 'settings_errors', get_settings_errors(), 30 );

	/**
	 * Redirect back to the settings page that was submitted
	 */
	$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
	wp_redirect( $goback );
	exit;
}

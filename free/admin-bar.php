<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

if ( ! secupress_get_module_option( 'advanced-settings_admin-bar', true , 'welcome' ) ) {
	return;
}

add_action( 'admin_bar_menu', 'secupress_admin_bar', 100 );
/**
 * Add menu in tool bar.
 *
 * @since 1.0
 *
 * @param (object) $wp_admin_bar WP_Admin_Bar object.
 */
function secupress_admin_bar( $wp_admin_bar ) {
	if ( ! current_user_can( secupress_get_capability() ) ) {
		return;
	}

	// Add a counter of scans with good result.
	$counts = secupress_get_scanner_counts();

	if ( secupress_get_module_option( 'advanced-settings_grade-system', true, 'welcome' ) && ( $counts['good'] || $counts['bad'] ) ) {
		$grade = sprintf( __( 'Grade %s', 'secupress' ), '<span class="letter">' . $counts['grade'] . '</span>' );
	} else {
		$grade = '';
	}

	// Parent.
	$wp_admin_bar->add_menu( array(
		'id'    => 'secupress',
		'title' => '<span class="ab-icon dashicons-shield-alt"></span><span class="screen-reader-text">' . SECUPRESS_PLUGIN_NAME . ' </span>' . $grade,
	) );

	// Scanners.
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress',
		'id' 	 => 'secupress-scanners',
		'title'  => __( 'Scanners', 'secupress' ),
		'href'   => esc_url( secupress_admin_url( 'scanners' ) ),
	) );
	// Sub-Scanners.
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress-scanners',
		'id' 	 => 'secupress-scanners-step1',
		'title'  => __( 'Step 1 – Site Health', 'secupress' ),
		'href'   => esc_url( secupress_admin_url( 'scanners', '&step=1' ) ),
	) );
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress-scanners',
		'id' 	 => 'secupress-scanners-step2',
		'title'  => __( 'Step 2 – Auto-Fix', 'secupress' ),
		'href'   => esc_url( secupress_admin_url( 'scanners', '&step=2' ) ),
		'meta'   => [ 'class' => secupress_is_pro() ? '' : 'secupress-pro-notice' ],
	) );
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress-scanners',
		'id' 	 => 'secupress-scanners-step3',
		'title'  => __( 'Step 3 – Manual Operations', 'secupress' ),
		'href'   => esc_url( secupress_admin_url( 'scanners', '&step=3' ) ),
	) );
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress-scanners',
		'id' 	 => 'secupress-scanners-step4',
		'title'  => __( 'Step 4 – Resolution Report', 'secupress' ),
		'href'   => esc_url( secupress_admin_url( 'scanners', '&step=4' ) ),
	) );
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress-scanners',
		'id' 	 => 'secupress-scanners-pdf',
		'title'  => __( 'Export Site Health report as PDF', 'secupress' ),
		'href'   => esc_url( secupress_admin_url( 'scanners', '#secupress-step-content-footer' ) ),
		'meta'   => [ 'class' => secupress_is_pro() ? '' : 'secupress-pro-notice' ],
	) );

	// Modules.
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress',
		'id' 	 => 'secupress-modules',
		'title'  => __( 'Modules', 'secupress' ),
		'href'   => esc_url( secupress_admin_url( 'modules' ) ),
	) );

	// Sub-Modules.
	$modules = secupress_get_modules();
	foreach ( $modules as $module_slug => $module ) {
		$wp_admin_bar->add_menu( array(
			'parent' => 'secupress-modules',
			'id' 	 => 'secupress-modules-' . $module_slug,
			'title'  => '<span class="ab-icon dashicons dashicons-' . $module['dashicon'] . '" style="font-size: 17px"></span>' . $module['title'],
			'href'   => ! isset( $module['href'] ) ?
						esc_url( secupress_admin_url( 'modules', $module_slug ) ) :
						esc_url( $module['href'] ),
			'meta'   => [ 'class'  => ! isset( $module['mark_as_pro'] ) || ! $module['mark_as_pro'] || secupress_is_pro() ? '' : 'secupress-pro-notice',
						'target' => ! isset( $module['href'] ) ? '' : '_blank', ]
		) );

		if ( empty( $module['submodules'] ) ) {
			continue;
		}

		foreach ( $module['submodules'] as $submodule_slug => $submodule ) {
			if ( ! $submodule ) {
				continue;
			}
			$wp_admin_bar->add_menu( array(
				'parent' => 'secupress-modules-' . $module_slug,
				'id'     => 'secupress-submodules-' . $submodule_slug,
				'title'  => str_replace( '*', '', '&rsaquo; ' . $submodule ),
				'href'   => esc_url( secupress_admin_url( 'modules', $module_slug . '#' . $submodule_slug ) ),
				'meta'   => [ 'class' => false === strpos( $submodule, '*' ) || secupress_is_pro() ? '' : 'secupress-pro-notice' ],
			) );
		}
	}

	if ( class_exists( 'SecuPress_Logs' ) ) {
		// Logs.
		$wp_admin_bar->add_menu( array(
			'parent' => 'secupress',
			'id' 	 => 'secupress-logs',
			'title'  => _x( 'Logs', 'post type general name', 'secupress' ),
			'href'   => esc_url( secupress_admin_url( 'logs' ) ),
		) );
		// Only add sub level menus if the 2 logs types are displayed.
		if ( 2 === count( SecuPress_Logs::get_log_types() ) ) {
			// Sub-Logs.
			$wp_admin_bar->add_menu( array(
				'parent' => 'secupress-logs',
				'id' 	 => 'secupress-logs-action',
				'title'  => __( 'Actions Logs', 'secupress' ),
				'href'   => esc_url( secupress_admin_url( 'logs' ) ),
			) );
			$wp_admin_bar->add_menu( array(
				'parent' => 'secupress-logs',
				'id' 	 => 'secupress-logs-404',
				'title'  => __( '404 Logs', 'secupress' ),
				'href'   => esc_url( secupress_admin_url( 'logs', '&tab=err404' ) ),
			) );
		}
	}

	if ( ! secupress_has_pro() ) {
		$title  = __( 'More Security', 'secupress' );
		$href   = secupress_admin_url( 'get-pro' );
		$target = '_blank';
	} else {
		$title = __( 'Add my license', 'secupress' );
		$href  = secupress_admin_url( 'modules' ) . '#module-secupress_display_apikey_options';
		$target = '_self';
	}

	if ( ! secupress_is_pro() ) {
		$wp_admin_bar->add_menu( array(
			'parent' => 'secupress',
			'id'     => 'secupress-modules-get-pro',
			'title'  => '<span class="ab-icon dashicons dashicons-star-filled" style="font-size: 17px"></span>' . $title,
			'href'   => $href,
			'meta'   => [ 'class'  => 'secupress-pro-notice',
						'target' => $target, ],
		) );
	}
}

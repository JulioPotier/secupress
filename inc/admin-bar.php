<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Add menu in tool bar.
 *
 * @since 1.0
 */
add_action( 'admin_bar_menu', 'secupress_admin_bar', 100 );

function secupress_admin_bar( $wp_admin_bar ) {
	$cap = apply_filters( 'secupress_capacity', 'administrator', 'adminbar' );

	if ( ! current_user_can( $cap ) ) {
		return;
	}

	// Add a counter of scans with good result.
	$count = '';
	$grade = '';
	$scans = secupress_get_scanners();

	if ( $scans ) {
		$count = 0;
		$total = secupress_get_tests();
		$total = count( array_merge( $total['high'], $total['medium'], $total['low'] ) );

		foreach ( $scans as $scan ) {
			if ( 'good' === $scan['status'] ) {
				++$count;
			}
		}

		$count = round( $count * 100 / $total );

		if ( $count >= 90 ) {
			$grade = 'A';
		} elseif ( $count >= 80 ) {
			$grade = 'B';
		} elseif ( $count >= 70 ) {
			$grade = 'C';
		} elseif ( $count >= 60 ) {
			$grade = 'D';
		} elseif ( $count >= 50 ) {
			$grade = 'E';
		} else {
			$grade = 'F';
		}

		$count = sprintf( ' <span class="ab-label secupress-percent"><span class="count">%d</span>%%</span>', $count );
		$grade = esc_attr( sprintf( __( 'Grade %s', 'secupress' ), $grade ) );
	}

	// Parent
	$wp_admin_bar->add_menu( array(
		'id'    => 'secupress',
		'title' => '<span class="ab-icon dashicons-shield-alt"></span><span class="screen-reader-text">' . SECUPRESS_PLUGIN_NAME . '</span>' . $count,
		'href'  => secupress_admin_url( 'dashboard' ),
		'meta'  => array(
			'title' => $grade,
		),
	) );

	// Settings
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress',
		'id' 	 => 'secupress-settings',
		'title'  => __( 'Settings', 'secupress' ),
		'href'   => secupress_admin_url( 'secupress_settings' ),
	) );

	// Modules
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress',
		'id' 	 => 'secupress-modules',
		'title'  => __( 'Modules', 'secupress' ),
		'href'   => secupress_admin_url( 'secupress_modules' ),
	) );

	// Scanners
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress',
		'id' 	 => 'secupress-scanners',
		'title'  => __( 'Scanners', 'secupress' ),
		'href'   => secupress_admin_url( 'secupress_scanner' ),
	) );
}

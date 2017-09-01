<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $is_apache, $is_nginx, $is_iis7;

$this->set_current_section( 'move-login' );
$this->add_section( __( 'Login Pages', 'secupress' ) );


$main_field_name  = $this->get_field_name( 'activated' );
$is_plugin_active = secupress_is_submodule_active( 'users-login', 'move-login' );

if ( is_plugin_active( 'sf-move-login/sf-move-login.php' ) ) {
	$this->add_field( array(
		'title'             => __( 'Move the login and admin pages', 'secupress' ),
		'label_for'         => $main_field_name,
		'plugin_activation' => true,
		'type'              => 'checkbox',
		'value'             => false,
		'disabled'          => true,
		'label'             => __( 'Yes, move the login and admin pages', 'secupress' ),
		'helpers'           => array(
			array(
				'type'        => 'warning',
				'description' => secupress_plugin_in_usage_string( 'sf-move-login/sf-move-login.php', 'options-general.php?page=move-login' ),
			),
		),
	) );

	return;
}
if ( is_plugin_active( 'wps-hide-login/wps-hide-login.php' ) ) {
	$this->add_field( array(
		'title'             => __( 'Move the login and admin pages', 'secupress' ),
		'label_for'         => $main_field_name,
		'plugin_activation' => true,
		'type'              => 'checkbox',
		'value'             => false,
		'disabled'          => true,
		'label'             => __( 'Yes, move the login and admin pages', 'secupress' ),
		'helpers'           => array(
			array(
				'type'        => 'warning',
				'description' => secupress_plugin_in_usage_string( 'wps-hide-login/wps-hide-login.php', 'options-general.php#whl_page' ),
			),
		),
	) );

	return;
}

$this->add_field( array(
	'title'             => __( 'Move the login and admin pages', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) $is_plugin_active,
	'label'             => __( 'Yes, move the login and admin pages', 'secupress' ),
) );


$labels    = secupress_move_login_slug_labels();
$login_url = site_url( '%%slug%%', 'login' );

foreach ( $labels as $slug => $label ) {
	$name    = $this->get_field_name( 'slug-' . $slug );
	$default = 'login' === $slug ? '' : $slug;
	$value   = secupress_get_module_option( $name, $slug, 'users-login' );
	$value   = sanitize_title( $value, $default, 'display' );

	if ( ! $value ) {
		if ( 'login' === $slug ) {
			// See `secupress_sanitize_move_login_slug_ajax_post_cb()`.
			$value = '##-' . strtoupper( sanitize_title( __( 'Choose your login URL', 'secupress' ), '', 'display' ) ) . '-##';
		} else {
			$value = $default;
		}
	}

	$this->add_field( array(
		'title'        => esc_html( $label ),
		'depends'      => $main_field_name,
		'label_for'    => $this->get_field_name( 'slug-' . $slug ),
		'type'         => 'text',
		'default'      => $default,
		'label_before' => '<span class="screen-reader-text">' . __( 'URL' ) . '</span>',
		'label_after'  => '<em class="hide-if-no-js">' . str_replace( '%%slug%%', '<strong class="dynamic-login-url-slug">' . $value . '</strong>', $login_url ) . '</em>',
	) );
}

/**
 * If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules for Move Login.
 */
if ( $is_plugin_active && function_exists( 'secupress_move_login_get_rules' ) ) {
	$message = false;

	// Nginx.
	if ( $is_nginx ) {
		/** Translators: 1 is a file name, 2 is a tag name. */
		$message = sprintf( __( 'You need to remove the following code from your %1$s file, inside the %2$s block:', 'secupress' ), '<code>nginx.conf</code>', '<code>server</code>' );
		$rules   = secupress_move_login_get_nginx_rules( secupress_move_login_get_rules() );
	}

	if ( $message ) {
		$this->add_field( array(
			'title'        => __( 'Rules', 'secupress' ),
			'description'  => $message,
			'depends'      => $main_field_name,
			'label_for'    => $this->get_field_name( 'rules' ),
			'type'         => 'textarea',
			'value'        => $rules,
			'attributes'   => array(
				'readonly' => 'readonly',
				'rows'     => substr_count( $rules, "\n" ) + 1,
			),
		) );
	}
}

unset( $main_field_name, $is_plugin_active, $labels, $message, $rules );

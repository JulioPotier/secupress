<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

global $is_apache, $is_nginx, $is_iis7;

$this->set_current_section( 'move-login' );
$this->add_section( __( 'Login Pages', 'secupress' ) );


$main_field_name  = $this->get_field_name( 'activated' );
$is_plugin_active = secupress_is_submodule_active( 'users-login', 'move-login' );

/**
* Allow some plugins to take over SecuPress settings if they are actually activated.
* @param (array) The plugins list ; format 'plugins-path/plugin-file.php' => 'admin-page.php#for-settings'
*/
$override_plugins = apply_filters( 'secupress.move-login.override-plugins', [ 'wps-hide-login/wps-hide-login.php' => 'options-general.php#whl_page' ] );
foreach ( $override_plugins as $plugin_path => $plugin_page) {
	if ( is_plugin_active( $plugin_path ) ) {
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
					'description' => secupress_plugin_in_usage_string( $plugin_path, $plugin_page ),
				),
			),
		) );

		return;
	}
}

/**
* If pretty permalinks are not active, do not let move login do its works
*/
$wp_rewrite = new WP_Rewrite();
if ( ! $wp_rewrite->using_permalinks() ) {
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
				'description' => sprintf( __( 'Your website is not using <b>Pretty Permalinks</b> but this module needs that. You can activate that in the <a href="%s">Permalinks Settings Page</a> and do not use "Plain" setting.', 'secupress' ), esc_url( admin_url( 'options-permalink.php' ) ) ),
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

if ( defined( 'SECUPRESS_ALLOW_LOGIN_ACCESS' ) && SECUPRESS_ALLOW_LOGIN_ACCESS ) {
	$this->add_field( array(
		'title'             => __( 'Move the login and admin pages', 'secupress' ),
		'label_for'         => $main_field_name,
		'type'              => 'html',
		'value'             => '',
		'helpers'           => array(
			array(
				'type'        => 'warning',
				'description' => sprintf( __( 'The %1$s constant is set, you cannot use the %2$s module.', 'secupress' ), '<code>SECUPRESS_ALLOW_LOGIN_ACCESS</code>', '<em>' . __( 'Move Login', 'secupress' ) . '</em>' ),
			),
		),
	) );
	return;
}

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

$this->add_field( [
	'title'        => __( 'What to do when the old page is triggered?', 'secupress' ),
	'depends'      => $main_field_name,
	'label_for'    => $this->get_field_name( 'whattodo' ),
	'type'         => 'radio',
	'options'      => [
		'sperror'      => __( 'Standard Error Message', 'secupress' ),
		'custom_error' => __( 'Custom Error Message', 'secupress' ),
		'custom_page'  => __( 'Custom Page', 'secupress' )
	],
] );

add_action( 'admin_footer', 'add_thickbox' );
$this->add_field( [
	'title'        => __( 'Preview', 'secupress' ),
	'type'         => 'html',
	'value'        => sprintf( '<a href="%2$s%1$s" target="_blank" class="thickbox"><img src="%2$s%1$s" height="150"></a>', __( 'secupress-movelogin-error-preview-en_US.png', 'secupress' ), SECUPRESS_ADMIN_IMAGES_URL ),
	'depends'      => $this->get_field_name( 'whattodo' ) . '_sperror',
] );

$this->add_field( [
	'title'        => __( 'Custom Message', 'secupress' ),
	'type'         => 'wpeditor',
	'label_for'    => $this->get_field_name( 'custom_error_content' ),
	'depends'      => $this->get_field_name( 'whattodo' ) . '_custom_error',
	'default'      => __( 'This page does not exist, has moved or you are not allowed to access it.', 'secupress' ) . "\n" .
					__( 'If you are Administrator and have been accidentally locked out, enter your email address here to unlock yourself.', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'Clean HTML allowed. The recovery form will be automatically added at the end of your content.', 'secupress' ),
		),
	),
] );

$this->add_field( [
	'title'        => __( 'Custom Page', 'secupress' ),
	'type'         => 'url',
	'attributes'   => [ 'class' => [ 'regular-text', 'wp_link_dialog' ] ],
	'label_for'    => $this->get_field_name( 'custom_page_url' ),
	'depends'      => $this->get_field_name( 'whattodo' ) . '_custom_page',
	'default'      => home_url(),
	'value'        => '' !== secupress_get_module_option( 'move-login_custom_page_url', '', 'users-login' ) ? secupress_get_module_option( 'move-login_custom_page_url', '', 'users-login' ) : home_url(),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'A custom page from your site, only.', 'secupress' ),
		),
	),
] );

/**
 * If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules for Move Login.
 */
if ( $is_plugin_active && function_exists( 'secupress_move_login_get_rules' ) && apply_filters( 'secupress.nginx.notice', true ) ) {
	$message = false;

	// Nginx.
	if ( $is_nginx ) {
		/** Translators: 1 is a file name, 2 is a tag name. */
		$message = sprintf( __( 'You need to add the following code from your %1$s file, inside the %2$s block:', 'secupress' ), '<code>nginx.conf</code>', '<code>server</code>' );
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

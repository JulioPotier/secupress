<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $is_apache, $is_nginx, $is_iis7;

$this->set_current_section( 'move-login' );
$this->add_section( __( 'Move Login', 'secupress' ) );


$field_name       = $this->get_field_name( 'activated' );
$main_field_name  = $field_name;
$is_plugin_active = secupress_is_submodule_active( 'users-login', 'move-login' );

$this->add_field(
	__( 'Move the login page', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'This will not totally hide the login form from humans, the main goal is to avoid bots to hit this URL.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) $is_plugin_active,
			'label'        => __( 'Yes, move the login page to avoid bad login attempts', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, move the login page to avoid bad login attempts', 'secupress' ),
		),
		array(
			'type'         => 'helper_warning',
			'name'         => $field_name,
			'description'  => secupress_get_deactivate_plugin_string( 'sf-move-login/sf-move-login.php' ),
		),
	)
);

$labels = secupress_move_login_slug_labels();

foreach( $labels as $slug => $label ) {
	$slug       = esc_attr( $slug );
	$field_name = $this->get_field_name( 'slug-' . $slug );

	$this->add_field(
		esc_html( $label ),
		array(
			'name'        => $field_name,
		),
		array(
			'depends'     => $main_field_name,
			array(
				'type'         => 'text',
				'default'      => $slug,
				'name'         => $field_name,
				'label'        => '<em>(' . sprintf( __( 'Default: %s', 'secupress' ), $slug ) . ')</em>',
				'label_for'    => $field_name,
				'label_screen' => __( 'page slug', 'secupress' ),
			),
		)
	);
}

$field_name = $this->get_field_name( 'wp-login-access' );
$options    = secupress_move_login_wplogin_access_labels();

$this->add_field(
	sprintf( __( 'Access to %s', 'secupress' ), '<code>wp-login.php</code>' ),
	array(
		'name'        => $field_name,
		'description' => __( 'When a not connected user attempts to access the old login page.', 'secupress' ),
	),
	array(
		'depends'     => $main_field_name,
		array(
			'type'         => 'radio',
			'options'      => $options,
			'default'      => 'error',
			'name'         => $field_name,
			'label_for'    => $field_name,
			'label_screen' => sprintf( __( 'Access to %s', 'secupress' ), '<code>wp-login.php</code>' ),
		),
	)
);

$field_name = $this->get_field_name( 'admin-access' );
$options    = secupress_move_login_admin_access_labels();

$this->add_field(
	__( 'Access to the administration area', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'When a not connected user attempts to access the old login page.', 'secupress' ),
	),
	array(
		'depends'     => $main_field_name,
		array(
			'type'         => 'radio',
			'options'      => $options,
			'default'      => 'redir-login',
			'name'         => $field_name,
			'label_for'    => $field_name,
			'label_screen' => __( 'Access to the administration area', 'secupress' ),
		),
	)
);


// If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules.

if ( $is_plugin_active && function_exists( 'secupress_move_login_file_is_writable' ) ) {
	$message = false;

	// Nginx
	if ( $is_nginx ) {
		/* translators: 1 is a file name, 2 is a tag name */
		$message = sprintf( __( 'You need to add the following code into your %1$s file, inside the %2$s block:', 'secupress' ), '<code>nginx.conf</code>', '<code>server</code>' );
		$rules   = secupress_move_login_get_nginx_rules( secupress_move_login_get_rules() );
		$rules   = "# BEGIN SecuPress move_login\n$rules\n# END SecuPress";
	}
	// Apache
	elseif ( $is_apache && ! secupress_move_login_file_is_writable( '.htaccess' ) ) {
		/* translators: %s is a file name */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code inside:', 'secupress' ), '<code>.htaccess</code>' );
		$rules   = secupress_move_login_get_apache_rules( secupress_move_login_get_rules() );
		$rules   = "# BEGIN SecuPress move_login\n$rules\n# END SecuPress";
	}
	// IIS7
	elseif ( $is_iis7 && ! secupress_move_login_file_is_writable( 'web.config' ) ) {
		/* translators: %s is a file name */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code inside:', 'secupress' ), '<code>web.config</code>' );
		$rules   = secupress_move_login_get_iis7_rules( secupress_move_login_get_rules() );
	}

	if ( $message ) {
		$field_name = $this->get_field_name( 'rules' );

		$this->add_field(
			__( 'Rules', 'secupress' ),
			array(
				'name'        => $field_name,
				'description' => $message,
			),
			array(
				'depends'     => $main_field_name,
				array(
					'type'         => 'textarea',
					'value'        => $rules,
					'name'         => $field_name,
					'label_for'    => $field_name,
					'label_screen' => __( 'Rules', 'secupress' ),
					'readonly'     => true,
					'rows'         => count( explode( "\n", $rules ) ) + 1,
				),
			)
		);
	}
}

unset( $options, $field_name, $main_field_name, $is_plugin_active, $labels, $message, $rules, $home_path );

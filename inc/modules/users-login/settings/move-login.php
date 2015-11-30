<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'move-login' );
$this->add_section( __( 'Move Login', 'secupress' ) );


$field_name      = $this->get_field_name( 'move-login' );
$main_field_name = $field_name;

$this->add_field(
	__( 'Move the login page', 'secupress' ),
	array(
		'name'        => $field_name,
		'description'  => __( 'This will not totally hide the login form from humans, the main goal is to avoid bots to hit this URL.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, move the login page to avoid bad login attempts', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, move the login page to avoid bad login attempts', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
		),
	)
);

$labels = array(
	'login'        => __( 'Log in' ),
	'logout'       => __( 'Log out' ),
	'register'     => __( 'Register' ),
	'lostpassword' => __( 'Lost Password' ),
	'resetpass'    => __( 'Password Reset' ),
);
$new_slugs = apply_filters( 'sfml_additional_slugs', array() );
if ( ! empty( $new_slugs ) ) {
	$new_slugs    = array_diff_key( $new_slugs, $labels );
	$labels = array_merge( $labels, $new_slugs );
}
foreach( $labels as $slug => $label ) {
	$field_name      = $this->get_field_name( 'link-' . esc_attr( $slug ) );
	$this->add_field(
		esc_html( $label ),
		array(
			'name'        => $field_name,
		),
		array(
			'depends'     => $main_field_name,
			array(
				'type'         => 'text',
				'default'      => esc_attr( $slug ),
				'name'         => $field_name . '_' . esc_attr( $slug ),
				'label'        => '<em>(' . sprintf( __( 'Default: %s', 'secupress' ), esc_attr( $slug ) ) . ')</em>',
				'label_for'    => $field_name . '_' . esc_attr( $slug ),
				'label_screen' => __( 'page slug', 'secupress' ),
			),
		)
	);
}

$field_name      = $this->get_field_name( 'wp-login_access' );
$options = array( 'error' => __( 'Display an error message', 'secupress' ), 'redir_404' => __( 'Redirect to a «Page not found» error page', 'secupress' ), 'redir_home' => __( 'Redirect to the home page', 'secupress' ) );
$this->add_field(
	sprintf( __( 'Access to %s', 'secupress' ), '<code>wp-login.php</code>' ),
	array(
		'name'        => $field_name,
		'description' => __( 'When a not connected user attempts to access the old login page.', 'secupress' ),
	),
	array(
		'depends'     => $main_field_name,
		array(
			'type'         => 'radios',
			'options'      => $options,
			'default'      => 'error',
			'name'         => $field_name,
			'label_for'    => $field_name,
			'label_screen' => sprintf( __( 'Access to %s', 'secupress' ), '<code>wp-login.php</code>' ),
		),
	)
);

$field_name      = $this->get_field_name( 'admin_access' );
$options = array( 'redir-login' => __( 'Do nothing, redirect to the new login page', 'secupress' ), 'error' => __( 'Display an error message', 'secupress' ), 'redir_404' => __( 'Redirect to a «Page not found» error page', 'secupress' ), 'redir_home' => __( 'Redirect to the home page', 'secupress' ) );
$this->add_field(
	__( 'Access to the administration area', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'When a not connected user attempts to access the old login page.', 'secupress' ),
	),
	array(
		'depends'     => $main_field_name,
		array(
			'type'         => 'radios',
			'options'      => $options,
			'default'      => 'error',
			'name'         => $field_name,
			'label_for'    => $field_name,
			'label_screen' => __( 'Access to administration area', 'secupress' ),
		),
	)
);
unset( $options );
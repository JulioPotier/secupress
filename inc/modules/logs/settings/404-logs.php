<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'pages-logs' );
$this->add_section( __( 'Pages Logs', 'secupress' ), array( 'with_save_button' => false ) );

$field_name      = $this->get_field_name( '404-logs' );
$main_field_name = $field_name;
$this->add_field(
	__( '404 Pages Logs', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( '404 pages are common, but it can also be some bots trying to find unsafe content on your website. You may want to know that.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, i want to log WordPress 404s', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, i want to log WordPress 404s', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( '', 'secupress' ),
		),
	)
);

$field_name = $this->get_field_name( 'wp-logs' );
$this->add_field(
	__( 'WordPress 404 Pages', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'These pages has been reach recently.', 'secupress' ),
	),
	array(
		'depends_on'       => $main_field_name,
		array(
			'type'         => '_404_logs',
		),
	)
);
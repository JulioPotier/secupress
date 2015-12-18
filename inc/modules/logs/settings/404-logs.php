<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( '404-logs' );
$this->add_section( __( 'Pages Logs', 'secupress' ) );

$field_name      = $this->get_field_name( 'activated' );
$main_field_name = $field_name;
$is_plugin_active = secupress_is_submodule_active( 'logs', '404-logs' );

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
			'value'        => (int) $is_plugin_active,
			'label'        => __( 'Yes, i want to log WordPress 404s', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, i want to log WordPress 404s', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
		),
	)
);


if ( class_exists( 'SecuPress_404_Logs' ) ) :

SecuPress_404_Logs::_maybe_include_list_class();

$field_name = $this->get_field_name( 'logs' );

$this->add_field(
	__( 'WordPress 404 Pages Logs', 'secupress' ),
	array(
		'name'        => $field_name,
		'field_type'  => array( SecuPress_404_Logs_List::get_instance(), 'output' ),
		'description' => __( 'These addresses have been reached recently.', 'secupress' ),
	),
	array(
		'depends'     => $main_field_name,
	)
);

endif;
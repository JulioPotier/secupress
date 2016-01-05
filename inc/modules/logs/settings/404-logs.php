<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( '404-logs' );
$this->add_section( __( 'Pages Logs', 'secupress' ) );


$main_field_name = $this->get_field_name( 'activated' );

$this->add_field( array(
	'title'        => __( '404 Pages Logs', 'secupress' ),
	'description'  => __( '404 pages are common, but it can also be some bots trying to find unsafe content on your website. You may want to know that.', 'secupress' ),
	'label_for'    => $main_field_name,
	'type'         => 'checkbox',
	'value'        => (int) secupress_is_submodule_active( 'logs', '404-logs' ),
	'label'        => __( 'Yes, i want to log WordPress 404s', 'secupress' ),
) );


if ( class_exists( 'SecuPress_404_Logs' ) ) :

	SecuPress_404_Logs::_maybe_include_list_class();

	$this->add_field( array(
		'title'        => __( 'WordPress 404 Pages Logs', 'secupress' ),
		'description'  => __( 'These addresses have been reached recently.', 'secupress' ),
		'depends'      => $main_field_name,
		'name'         => $this->get_field_name( 'logs' ),
		'field_type'   => array( SecuPress_404_Logs_List::get_instance(), 'output' ),
	) );

endif;

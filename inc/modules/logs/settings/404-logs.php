<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $wpdb;

$this->set_current_section( '404-logs' );
$this->add_section( __( 'Pages Logs', 'secupress' ) );


$main_field_name = $this->get_field_name( 'activated' );

$this->add_field( array(
	'title'             => __( '404 Pages Logs', 'secupress' ),
	'description'       => __( '404 pages are common, but it can also be some bots trying to find unsafe content on your website. You may want to know that.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'logs', '404-logs' ),
	'label'             => __( 'Yes, i want to log WordPress 404s', 'secupress' ),
) );


if ( class_exists( 'SecuPress_404_Logs' ) ) :

	$post_type = SecuPress_404_Logs::get_instance()->get_post_type();
	$logs      = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(ID) FROM $wpdb->posts WHERE post_type = %s", $post_type ) );

	if ( $logs ) {
		$log_type = SecuPress_404_Logs::get_instance()->get_log_type();
		$text     = sprintf( _n( '%s error 404.', '%s errors 404.', $logs, 'secupress' ), number_format_i18n( $logs ) );
		$text     = '<a href="' . esc_url( SecuPress_404_Logs::get_log_type_url( $log_type ) ) . '">' . $text . '</a>';
	} else {
		$text = __( 'Nothing happened yet.' );
	}

	$this->add_field( array(
		'title'        => '',
		'description'  => __( 'What happened on your WordPress website?', 'secupress' ),
		'depends'      => $main_field_name,
		'name'         => $this->get_field_name( 'logs-err404' ),
		'type'         => 'html',
		'value'        => "<p>$text</p>\n",
	) );

endif;

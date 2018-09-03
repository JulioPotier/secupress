<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'notifications' );
$this->add_section( __( 'Email Notifications', 'secupress' ) );


// Types.
$activated_field_name = $this->get_field_name( 'types' );

if ( secupress_is_submodule_active( 'logs', 'action-logs' ) ) {
	$help = sprintf( __( 'If you want to get the alerts here in the back-end, %s.', 'secupress' ), '<a href="' . esc_url( secupress_admin_url( 'logs' ) ) . '">' . __( 'take a look at the WordPress action logs', 'secupress' ) . '</a>' );
} else {
	$help = sprintf( __( 'If you want to get the alerts here in the back-end, %s.', 'secupress' ), '<a href="' . esc_url( secupress_admin_url( 'modules', 'logs' ) ) . '#row-action-logs_activated">' . __( 'please activate the WordPress action logs', 'secupress' ) . '</a>' );
}

// E-mails.
$this->add_field( array(
	'title'        => __( 'Choose the email addresses to notify', 'secupress' ),
	'name'         => $this->get_field_name( 'emails' ),
	'type'         => 'textarea',
	'attributes'   => array( 'rows' => 3 ),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'One address per line.', 'secupress' ),
		),
	),
) );

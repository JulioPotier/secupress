<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'notifications' );
$this->add_section( __( 'Types of Notification', 'secupress' ) );


// Types.
$activated_field_name = $this->get_field_name( 'types' );

if ( secupress_is_submodule_active( 'logs', 'action-logs' ) ) {
	$help = sprintf( __( 'If you want to get the alerts here in the back-end, %s.', 'secupress' ), '<a href="' . esc_url( secupress_admin_url( 'logs' ) ) . '">' . __( 'take a look at the WordPress action logs', 'secupress' ) . '</a>' );
} else {
	$help = sprintf( __( 'If you want to get the alerts here in the back-end, %s.', 'secupress' ), '<a href="' . esc_url( secupress_admin_url( 'modules', 'logs' ) ) . '#row-action-logs_activated">' . __( 'please activate the WordPress action logs', 'secupress' ) . '</a>' );
}

$this->add_field( array(
	'title'        => __( 'Choose which service should be used', 'secupress' ),
	'description'  => __( 'A least one type of notification must be chosen here before activating alerts below.', 'secupress' ),
	'name'         => $activated_field_name,
	'type'         => 'checkboxes',
	'label_screen' => __( 'How to alert you?', 'secupress' ),
	'options'      => secupress_alert_types_labels(),
	'helpers'      => array(
		array(
			'type'        => 'help',
			'description' => $help,
		),
	),
) );


// E-mails.
$this->add_field( array(
	'title'        => __( 'Choose the addresses to notify', 'secupress' ),
	'description'  => __( 'A least <strong>two distinct addresses</strong> must be chosen.', 'secupress' ),
	'depends'      => $activated_field_name . '_email',
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


if ( secupress_is_pro() ) :

	// SMS.
	$this->add_field( array(
		'title'        => __( 'SMS', 'secupress' ),
		'depends'      => $activated_field_name . '_sms',
		'label_for'    => $this->get_field_name( 'sms_number' ),
		'type'         => 'tel',
		'label'        => __( 'Phone number:', 'secupress' ),
	) );


	// Push.
	$this->add_field( array(
		'title'        => __( 'Push notification', 'secupress' ),
		'depends'      => $activated_field_name . '_push',
		'label_for'    => $this->get_field_name( 'push' ),
		'type'         => 'text',
		'label'        => __( 'I don\'t know what I need yet:', 'secupress' ), // ////.
	) );


	// Slack.
	$this->add_field( array(
		'title'        => __( 'Slack', 'secupress' ),
		'depends'      => $activated_field_name . '_slack',
		'label_for'    => $this->get_field_name( 'slack' ),
		'type'         => 'text',
		'label'        => __( 'I don\'t know what I need yet:', 'secupress' ), // ////.
	) );


	// Twitter.
	$this->add_field( array(
		'title'        => __( 'Twitter', 'secupress' ),
		'depends'      => $activated_field_name . '_twitter',
		'label_for'    => $this->get_field_name( 'twitter' ),
		'type'         => 'text',
		'label'        => __( 'I don\'t know what I need yet:', 'secupress' ), // ////.
	) );

endif;

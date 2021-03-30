<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'notifications' );
$this->add_section( __( 'Notifications', 'secupress' ) );

// Types.
$activated_field_name = $this->get_field_name( 'types' );

if ( secupress_is_submodule_active( 'logs', 'action-logs' ) ) {
	$help = sprintf( __( 'If you want to get the alerts here in the back-end, %s.', 'secupress' ), '<a href="' . esc_url( secupress_admin_url( 'logs' ) ) . '">' . __( 'take a look at the WordPress action logs', 'secupress' ) . '</a>' );
} else {
	$help = sprintf( __( 'If you want to get the alerts here in the back-end, %s.', 'secupress' ), '<a href="' . esc_url( secupress_admin_url( 'modules', 'logs' ) ) . '#row-action-logs_activated">' . __( 'please activate the WordPress action logs', 'secupress' ) . '</a>' );
}

// E-mails.
$this->add_field( array(
	'title'        => __( 'Email Notifications', 'secupress' ),
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

// Slack webhook
$helpers   = [];
$helpers[] = [
				'type'        => 'help',
				'description' => __( 'Read <a href="https://docs.secupress.me/article/178-slack-notifications">our simple documentation page</a> to know how to get your Webhook Link for Slack.', 'secupress' ),
			];
$url       = secupress_get_module_option( 'notification-types_slack', false, 'alerts' );
$accepted  = secupress_get_option( 'notification-types_slack', false );
if ( $url ) {
	if ( $accepted ) {
		$helpers = [ [
						'type'        => 'description',
						'description' => '<span class="dashicons dashicons-yes-alt"></span> ' . __( 'Slack Webhook Notifications have been accepted.', 'secupress' ),
					] ];
	} else {
		$helpers[] = [
						'type'        => 'warning',
						'description' => ! apply_filters( 'secupress.notifications.slack.bypass', false ) ? __( 'You know have to accept the Slack Webhook Notifications in your dedicated channel.', 'secupress' ) : '',
					];
	}
}
$this->add_field( array(
	'title'        => __( 'Slack Webhook Notifications', 'secupress' ),
	'name'         => $this->get_field_name( 'slack' ),
	'type'         => 'url',
	'attributes'   => [ 'class' => 'large-text', 'placeholder' => 'https://hooks.slack.com/services/…/…/…' ],
	'helpers'      => $helpers,
) );

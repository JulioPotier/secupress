<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

global $wpdb;

$this->set_current_section( 'logs' );
$this->add_section( _x( 'Logs', 'post type general name', 'secupress' ), array( 'with_save_button' => false ) );


/**
 * WP actions.
 */
$main_field_name = $this->get_field_name( 'action-logs-activated' );

$this->add_field( array(
	'title'             => __( 'WordPress action logs', 'secupress' ),
	'description'       => __( 'What happened on your WordPress website? By activating this module, most sensitive actions will be logged.', 'secupress' ),
	'label_for'         => $main_field_name,
	'type'              => 'activate_action_logs',
	'label'             => __( 'Yes, log WordPress actions', 'secupress' ),
) );

if ( class_exists( 'SecuPress_Action_Logs' ) ) :

	$criticities = array(
		'high'   => _n_noop( 'High criticity <span class="count">(%s)</span>',   'High criticity <span class="count">(%s)</span>',   'secupress' ),
		'normal' => _n_noop( 'Normal criticity <span class="count">(%s)</span>', 'Normal criticity <span class="count">(%s)</span>', 'secupress' ),
		'low'    => _n_noop( 'Low criticity <span class="count">(%s)</span>',    'Low criticity <span class="count">(%s)</span>',    'secupress' ),
	);
	$post_type   = SecuPress_Action_Logs::get_instance()->get_post_type();
	$logs        = $wpdb->get_results( $wpdb->prepare( "SELECT post_status AS critic, COUNT(ID) AS count FROM $wpdb->posts WHERE post_type = %s GROUP BY post_status", $post_type ), OBJECT_K );

	if ( $logs ) {
		$log_type = SecuPress_Action_Logs::get_instance()->get_log_type();
		$page_url = SecuPress_Action_Logs::get_log_type_url( $log_type );
		$total    = 0;

		foreach ( $criticities as $criticity => $label ) {
			if ( isset( $logs[ $criticity ] ) ) {
				$logs[ $criticity ]->count = (int) $logs[ $criticity ]->count;
				$total += $logs[ $criticity ]->count;

				$tmp    = translate_nooped_plural( $label, $logs[ $criticity ]->count, 'secupress' );
				$tmp    = sprintf( $tmp, number_format_i18n( $logs[ $criticity ]->count ) );
				$text[] = '<a href="' . esc_url( add_query_arg( 'critic', $criticity, $page_url ) ) . '">' . $tmp . '</a>';
			}
		}

		$total = '<a href="' . esc_url( $page_url ) . '">' . sprintf( __( 'Total: %s', 'secupress' ), number_format_i18n( $total ) ) . '</a>';
		array_unshift( $text, $total );

		$text = implode( '<br/>', $text );
	} else {
		$text = __( 'Nothing happened yet.', 'secupress' );
	}

	$this->add_field( array(
		'title'        => '',
		'description'  => __( 'What happened on your WordPress website?', 'secupress' ),
		'depends'      => $main_field_name,
		'name'         => $this->get_field_name( 'logs-action' ),
		'type'         => 'html',
		'value'        => "<p>$text</p>\n",
	) );

endif;


/**
 * WP 404s.
 */
$main_field_name = $this->get_field_name( '404-logs-activated' );

$this->add_field( array(
	'title'             => __( '404 Error Pages Log', 'secupress' ),
	'description'       => __( '404 Error pages are common, but it can also be some bots trying to find insecure content on your website. You may want to know that.', 'secupress' ),
	'label_for'         => $main_field_name,
	'type'              => 'activate_404_logs',
	'label'             => __( 'Yes, log WordPress 404s', 'secupress' ),
) );


if ( class_exists( 'SecuPress_404_Logs' ) ) :

	$post_type = SecuPress_404_Logs::get_instance()->get_post_type();
	$logs      = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(ID) FROM $wpdb->posts WHERE post_type = %s", $post_type ) );

	if ( $logs ) {
		$log_type = SecuPress_404_Logs::get_instance()->get_log_type();
		$text     = sprintf( _n( '%s error 404.', '%s errors 404.', $logs, 'secupress' ), number_format_i18n( $logs ) );
		$text     = '<a href="' . esc_url( SecuPress_404_Logs::get_log_type_url( $log_type ) ) . '">' . $text . '</a>';
	} else {
		$text = __( 'Nothing happened yet.', 'secupress' );
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


/**
 * WP HTTP Requests.
$main_field_name = $this->get_field_name( 'http-logs-activated' );

$this->add_field( array(
	'title'             => __( 'HTTP Requests Log', 'secupress' ),
	'description'       => __( 'Every HTTP request triggered from WordPress can be tracked here.', 'secupress' ),
	'label_for'         => $main_field_name,
	'type'              => 'activate_http_logs',
	'label'             => __( 'Yes, log WordPress HTTP requests', 'secupress' ),
) );


if ( class_exists( 'SecuPress_HTTP_Logs' ) ) :

	$post_type = SecuPress_HTTP_Logs::get_instance()->get_post_type();
	$logs      = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(ID) FROM $wpdb->posts WHERE post_type = %s", $post_type ) );

	if ( $logs ) {
		$log_type = SecuPress_HTTP_Logs::get_instance()->get_log_type();
		$text     = sprintf( _n( '%s HTTP Request.', '%s HTTP Requests.', $logs, 'secupress' ), number_format_i18n( $logs ) );
		$text     = '<a href="' . esc_url( SecuPress_HTTP_Logs::get_log_type_url( $log_type ) ) . '">' . $text . '</a>';
	} else {
		$text     = __( 'Nothing happened yet.', 'secupress' );
	}

	$this->add_field( array(
		'title'        => '',
		'description'  => __( 'What happened on your WordPress website?', 'secupress' ),
		'depends'      => $main_field_name,
		'name'         => $this->get_field_name( 'logs-http' ),
		'type'         => 'html',
		'value'        => "<p>$text</p>\n",
	) );

endif;

$this->add_field( array(
	'title'        => '',
	'type'         => 'http_logs_restrictions',
) );
 */

<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $wpdb;

$this->set_current_section( 'action-logs' );
$this->add_section( _x( 'Logs', 'post type general name', 'secupress' ), array( 'with_save_button' => false ) );


$main_field_name = $this->get_field_name( 'activated' );

$this->add_field( array(
	'title'             => __( 'WordPress Logs', 'secupress' ),
	'description'       => __( 'What happened on your WordPress website? By activating this module, most sensible actions will be recorded, lightly.', 'secupress' ),
	'label_for'         => $main_field_name,
	'type'              => 'activate_action_logs',
	'label'             => __( 'Yes, i want to log WordPress actions', 'secupress' ),
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
		$text = __( 'Nothing happened yet.' );
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

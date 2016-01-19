<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $wpdb;

$this->set_current_section( 'action-logs' );
$this->add_section( _x( 'Logs', 'post type general name', 'secupress' ) );


$main_field_name = $this->get_field_name( 'activated' );

$this->add_field( array(
	'title'        => __( 'WordPress Logs', 'secupress' ),
	'description'  => __( 'What happened on your WordPress website? By activating this module, most sensible actions will be recorded, lightly.', 'secupress' ),
	'label_for'    => $main_field_name,
	'type'         => 'checkbox',
	'value'        => (int) secupress_is_submodule_active( 'logs', 'action-logs' ),
	'label'        => __( 'Yes, i want to log WordPress actions', 'secupress' ),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'We will not log post action like creation or update but rather password and profile update, email changes, new administrator user, admin has logged in...', 'secupress' ),
		),
	),
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
		foreach ( $criticities as $criticity => $label ) {
			if ( isset( $logs[ $criticity ] ) ) {
				$tmp    = translate_nooped_plural( $label, (int) $logs[ $criticity ]->count, 'secupress' );
				$text[] = sprintf( $tmp, number_format_i18n( (int) $logs[ $criticity ]->count ) );
			}
		}
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

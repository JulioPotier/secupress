<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'database' );
$this->add_section( __( 'WordPress Database', 'secupress' ) );


global $wpdb;
$button_id = secupress_is_pro() ? '' : '#';
$disabled  = secupress_is_pro() ? '' : 'disabled="disabled" ';
$this->add_field( array(
	'title'             => __( 'Change WordPress Database Prefix', 'secupress' ),
	'description'       => __( 'You may need to change it manually.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'db_prefix' ),
	'type'              => 'text',
	'attributes'        => [ 'pattern' => '[a-z0-9_]{0,}', 'maxlength' => 12 ],
	'label_after'       => ' <button ' . $disabled . 'id="' . $button_id . 'secupress-database-prefix-generate" type="button" class="button button-small button-secondary secupress-button light">' . __( 'Generate one', 'secupress' ) . '</button>',
	'helpers'           => array(
		array(
			'type'        => 'help',
			'description' => secupress_is_pro() ? __( 'Format rules:<ul><li>Only letters, numbers, and <code>_</code> allowed.</li><li>At least 1 letter or 1 number, 12 chars max.</li><li>Do not use <code>wp_</code> or <code>wordpress_</code>.</li><li>A <code>_</code> will be appended if not present.</li></ul>', 'secupress' ) : '',
		),
	),
) );

if ( secupress_is_pro() ) {
	$this->add_field( array(
		'title'             => __( 'Which tables to rename?', 'secupress' ),
		'label_for'         => $this->get_field_name( 'tables_selection' ),
		'type'              => 'tables_selection',
	) );
}

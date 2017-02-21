<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->set_current_section( 'support' );
$this->add_section( __( 'Support', 'secupress' ), array( 'with_save_button' => false ) );

$check_field_name = $this->get_field_name( 'doc-read' );

$this->add_field( array(
	'title'             => __( 'Documentation first', 'secupress' ),
	'type'              => 'checkbox',
	'name'              => $check_field_name,
	'label'             => sprintf(
		/** Translators: %s is "documentation". */
		__( 'I\'ve read the %s, and I agree to allow SecuPress to automatically detect my WordPress version and list of enabled plugins when I submit this form.', 'secupress' ),
		sprintf( '<a href="%s" target="_blank">%s</a>', esc_url( __( 'http://docs.secupress.me/', 'secupress' ) ), __( 'documentation', 'secupress' ) )
	),
) );

$scanner = '';

if ( ! empty( $_GET['scanner'] ) ) {
	$scanner  = sanitize_key( $_GET['scanner'] );
	$scanners = secupress_get_scanners();
	$scanners = call_user_func_array( 'array_merge', $scanners );
	$scanners = array_combine( array_map( 'strtolower', $scanners ), $scanners );

	if ( ! empty( $scanners[ $scanner ] ) && file_exists( secupress_class_path( 'scan', $scanners[ $scanner ] ) ) ) {

		secupress_require_class( 'scan' );
		secupress_require_class( 'scan', $scanners[ $scanner ] );

		$class_name = 'SecuPress_Scan_' . $scanners[ $scanner ];
		$scanner    = '<input type="hidden" name="secupress_' . $this->modulenow . '_settings[' . $this->get_field_name( 'scanner' ) . ']" value="' . $scanner . '" /><br/>';
		$scanner   .= sprintf( __( 'Scanner: %s', 'secupress' ), $class_name::get_instance()->title );
	} else {
		$scanner = '';
	}
}

// If the form was previously submitted without the checkbox being checked, the submitted data is stored in a transient.
$support_form = get_site_transient( 'secupress_support_form' );

$this->add_field( array(
	'title'             => __( 'Summary', 'secupress' ),
	'type'              => 'text',
	'size'              => 'large',
	'attributes'        => array( 'class' => 'large-text' ),
	'name'              => $this->get_field_name( 'summary' ),
	'depends'           => $check_field_name,
	'value'             => ! empty( $support_form['summary'] ) ? $support_form['summary'] : null,
	'helpers' => array(
		array(
			'type'        => 'description',
			'description' => $scanner,
		),
	),
) );

$this->add_field( array(
	'title'             => __( 'Description', 'secupress' ),
	'type'              => 'textarea',
	'name'              => $this->get_field_name( 'description' ),
	'depends'           => $check_field_name,
	'rows'              => 10,
	'value'             => ! empty( $support_form['description'] ) ? $support_form['description'] : null,
	'default'           => __( 'Please provide the specific url(s) where we can see each issue. e.g. the request doesn\'t work on this page: example.com/this-page', 'secupress' ) . "\n\n" .
	                       __( 'Please let us know how we will recognize the issue or can reproduce the issue. What is supposed to happen, and what is actually happening instead?', 'secupress' ) . "\n",
) );

$this->add_field( array(
	'type'              => 'submit',
	'label'             => __( 'Submit the ticket', 'secupress' ),
	'name'              => $this->get_field_name( 'submit' ),
	'depends'           => $check_field_name,
) );

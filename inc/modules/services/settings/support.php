<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'support' );
$this->add_section( __( 'Support', 'secupress' ), array( 'with_save_button' => false ) );

$main_field_name = $this->get_field_name( 'doc-read' );

$this->add_field( array(
	'title'             => __( 'Documentation first', 'secupress' ),
	'type'              => 'checkbox',
	'name'              => $main_field_name,
	'label'             => sprintf( __( 'I\'ve read the <a href="%s" target="_blank">documentation</a>, and I agree to allow SecuPress to automatically detect my WordPress version and list of enabled plugins when I submit this form.', 'secupress' ), '#////' ),
	'label_for'         => $main_field_name,
) );

$this->add_field( array(
	'title'             => __( 'Summary', 'secupress' ),
	'type'              => 'text',
	'size'              => 'large',
	'attributes'        => array( 'class' => 'large-text' ),
	'name'              => $this->get_field_name( 'summary' ),
	'depends'           => $main_field_name,
) );

$this->add_field( array(
	'title'             => __( 'Description', 'secupress' ),
	'type'              => 'textarea',
	'name'              => $this->get_field_name( 'description' ),
	'depends'           => $main_field_name,
	'rows'              => 10,
	'default'           => __( 'Please provide the specific url(s) where we can see each issue. e.g. the request doesn\'t work on this page: example.com/this-page', 'secupress' ) . "\n\n" .
	                       __( 'Please let us know how we will recognize the issue or can reproduce the issue. What is supposed to happen, and what is actually happening instead?', 'secupress' ) . "\n",
) );

$this->add_field( array(
	'type'              => 'submit',
	'label'             => __( 'Submit the ticket', 'secupress' ),
	'name'              => $this->get_field_name( 'submit' ),
	'depends'           => $main_field_name,
) );

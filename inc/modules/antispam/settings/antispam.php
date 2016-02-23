<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'antispam' );
$this->add_section( __( 'Anti Spam Rules', 'secupress' ) );


$field_name       = $this->get_field_name( 'antispam' );
$main_field_name  = $field_name . '_fightspam';
$is_plugin_active = array();

if ( secupress_is_submodule_active( 'antispam', 'fightspam' ) ) {
	$is_plugin_active[] = 'fightspam';
}
if ( secupress_is_submodule_active( 'antispam', 'remove-comment-feature' ) ) {
	$is_plugin_active[] = 'remove-comment-feature';
}

$this->add_field( array(
	'title'             => __( 'Anti Spam', 'secupress' ),
	'description'       => __( 'If you do not activate this anti-spam or remove the comment feature, please, activate another anti-spam plugin for your security!', 'secupress' ),
	'name'              => $field_name,
	'plugin_activation' => true,
	'type'              => 'radioboxes',
	'value'             => $is_plugin_active,
	'label_screen'      => __( 'Which anti-spam do you need', 'secupress' ),
	'options'           => array(
		'fightspam'              => __( 'I <strong>need</strong> this to help my website fighting comment spam', 'secupress' ),
		'remove-comment-feature' => __( 'I <strong>do not need</strong> comments on my website, remove all the comment features.', 'secupress' ),
	),
	'helpers' => array(
		array(
			'depends'     => $field_name . '_fightspam',
			'type'        => 'description',
			'description' => __( 'An anti-usurpation system will also be activated: registered users will be able to comment using their username and email only if they are logged in.', 'secupress' ),
		),
		array(
			'depends'     => $field_name . '_remove-comment-feature',
			'type'        => 'warning',
			'description' => secupress_get_deactivate_plugin_string( 'no-comment/no-comment.php' ),
		),
	),
) );


$options = array(
	'spam'  => __( 'Only <strong>mark it as spam</strong>', 'secupress' ),
	'trash' => __( '<strong>Delete permanently</strong> any spam', 'secupress' ),
);

if ( defined( 'EMPTY_TRASH_DAYS' ) && is_numeric( EMPTY_TRASH_DAYS ) && EMPTY_TRASH_DAYS > 0 ) {
	$options['trash'] = sprintf( __( '<strong>Send to trash</strong> any spam and delete it after %s days', 'secupress' ), EMPTY_TRASH_DAYS );
}

$this->add_field( array(
	'title'        => __( 'Handling Spam', 'secupress' ),
	'description'  => __( 'Usually WordPress keeps spam in the database, using the deletion setting, you will free some database storage usage.', 'secupress' ),
	'depends'      => $main_field_name,
	'name'         => $this->get_field_name( 'mark-as' ),
	'type'         => 'radios',
	'options'      => $options,
	'default'      => 'spam',
	'label_screen' => __( 'How to mark spam', 'secupress' ),
) );
unset( $options );


$this->add_field( array(
	'title'        => __( 'Shortcode usage', 'secupress' ),
	'description'  => __( 'A <a href="https://codex.wordpress.org/Shortcode" target="_blank">shortcode</a> can create macros to be used in a post\'s content.', 'secupress' ),
	'depends'      => $main_field_name,
	'label_for'    => $this->get_field_name( 'block-shortcodes' ),
	'type'         => 'checkbox',
	'label'        => __( 'Yes, mark as spam any comment using any shortcode', 'secupress' ),
	'helpers' => array(
		array(
			'type'        => 'description',
			'description' => __( '<em>BBcodes</em> and <em>shortcodes</em> are lookalikes, both will be blocked. A shortcode looks like <code>[this]</code>.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'        => __( 'Improve the Blacklist Comments from WordPress', 'secupress' ),
	'description'  => __( 'You can improve the list of bad words that will change some comment into a detected spam.', 'secupress' ),
	'depends'      => $main_field_name,
	'label_for'    => $this->get_field_name( 'better-blacklist-comment' ),
	'type'         => 'checkbox',
	'label'        => __( 'Yes, i want to use a better blacklist comments to detect spams', 'secupress' ),
	'disabled'     => ! is_readable( SECUPRESS_INC_PATH . 'data/spam-blacklist.data' ),
	'helpers' => array(
		array(
			'type'        => 'description',
			'description' => __( 'This will add more than 20,000 words in different languages.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => ! is_readable( SECUPRESS_INC_PATH . 'data/spam-blacklist.data' ) ? sprintf( __( 'As long as the following file is not readable, this feature can\'t be used: %s', 'secupress' ), '<code>' . SECUPRESS_INC_PATH . 'data/spam-blacklist.data</code>' ) : null,
		),
	),
) );


$this->add_field( array(
	'title'        => __( 'About Pingbacks & Trackbacks', 'secupress' ),
	'description'  => __( 'If you do not especially use Pingbacks & Trackbacks, you can disable their usage.', 'secupress' ),
	'depends'      => $main_field_name,
	'label_for'    => $this->get_field_name( 'forbid-pings-trackbacks' ),
	'type'         => 'checkbox',
	'label'        => __( '<strong>Forbid</strong> the usage of Pingbacks & Trackbacks', 'secupress' ),
	'helpers' => array(
		array(
			'type'        => 'description',
			'description' => __( 'it will also hide all Pingbacks & Trackbacks from your post comments.', 'secupress' ),
		),
	),
) );

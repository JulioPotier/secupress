<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'antispam' );
$this->add_section( __( 'Anti-Spam Rules', 'secupress' ) );


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
	'title'             => __( 'Anti-Spam', 'secupress' ),
	'description'       => __( 'If you choose not to activate this anti-spam module or remove the comment feature, we recommend activating another anti-spam plugin for added security!', 'secupress' ),
	'name'              => $field_name,
	'plugin_activation' => true,
	'type'              => 'radioboxes',
	'value'             => $is_plugin_active,
	'default'           => array(),
	'label_screen'      => __( 'Which anti-spam do you need', 'secupress' ),
	'options'           => array(
		'fightspam'              => __( 'Yes, comments <strong>are required</strong> on my website to combat comment spam', 'secupress' ),
		'remove-comment-feature' => __( 'No, comments <strong>are not required</strong> on my website. Please remove all the comment features', 'secupress' ),
	),
	'helpers' => array(
		array(
			'depends'     => $field_name . '_fightspam',
			'type'        => 'description',
		),
		array(
			'depends'     => $field_name . '_remove-comment-feature',
			'type'        => 'warning',
			'description' => secupress_get_deactivate_plugin_string( 'no-comment/no-comment.php' ),
		),
	),
) );


$options = array(
	'spam'  => __( 'Only <strong>mark as spam</strong>', 'secupress' ),
	'trash' => __( '<strong>Permanently delete</strong> any spam', 'secupress' ),
);

if ( defined( 'EMPTY_TRASH_DAYS' ) && is_numeric( EMPTY_TRASH_DAYS ) && EMPTY_TRASH_DAYS > 0 ) {
	$options['trash'] = sprintf( _n( '<strong>Send spam to trash</strong> and delete it after %s day', '<strong>Send spam to trash</strong> and delete it after %s days', EMPTY_TRASH_DAYS, 'secupress' ), EMPTY_TRASH_DAYS );
}

$this->add_field( array(
	'title'        => __( 'Handling Spam', 'secupress' ),
	'description'  => __( 'Typically, WordPress stores spam in the database. By enabling the deletion setting, you can free up database storage space.', 'secupress' ),
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
	'description'  => sprintf( __( 'A <a href="%s" target="_blank">shortcode</a> can generate code to be used in a post’s content.', 'secupress' ), 'https://developer.wordpress.org/plugins/shortcodes/' ),
	'depends'      => $main_field_name,
	'label_for'    => $this->get_field_name( 'block-shortcodes' ),
	'type'         => 'checkbox',
	'label'        => __( 'Yes, mark as spam any comment containing any shortcode or BBCode', 'secupress' ),
	'helpers' => array(
		array(
			'type'        => 'description',
			'description' => __( '<em>BBcodes</em> and <em>shortcodes</em> are similar in appereance; both will be blocked. A shortcode typically appears as <code>[this]</code>.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'        => __( 'Improve the WordPress comments disallowed terms', 'secupress' ),
	'description'  => __( 'You can improve the list of bad words that will flag comments as spam.', 'secupress' ),
	'depends'      => $main_field_name,
	'label_for'    => $this->get_field_name( 'better-blacklist-comment' ),
	'type'         => 'checkbox',
	'label'        => __( 'Yes, implement enhanced comment filtering with disallowed terms to detect spam', 'secupress' ),
	'disabled'     => ! is_readable( SECUPRESS_INC_PATH . 'data/spam-disallowed-terms.data' ),
	'helpers' => array(
		array(
			'type'        => 'description',
			'description' => __( 'Add more than 20,000 words in different languages.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => ! is_readable( SECUPRESS_INC_PATH . 'data/spam-disallowed-terms.data' ) ? sprintf( __( 'As long as the %s file is not readable, this feature can’t be used.', 'secupress' ), '<code>' . SECUPRESS_INC_PATH . 'data/spam-disallowed-terms.data</code>' ) : null,
		),
	),
) );


$this->add_field( array(
	'title'        => __( 'About Pingbacks & Trackbacks', 'secupress' ),
	'description'  => __( 'If you do not especially use Pingbacks & Trackbacks, you can disable them.', 'secupress' ),
	'depends'      => $main_field_name,
	'label_for'    => $this->get_field_name( 'forbid-pings-trackbacks' ),
	'type'         => 'checkbox',
	'label'        => __( 'Yes, <strong>forbid</strong> the usage of Pingbacks & Trackbacks', 'secupress' ),
	'helpers' => array(
		array(
			'type'        => 'description',
			'description' => __( 'It will also hide all Pingbacks & Trackbacks from your post comments.', 'secupress' ),
		),
	),
) );

$this->add_field( array(
	'title'        => __( 'Delay before posting a comment', 'secupress' ),
	'description'  => __( 'A human has to read the post then write a comment before posting. Let them wait 30 secondes before posting.', 'secupress' ),
	'depends'      => $main_field_name,
	'label_for'    => $this->get_field_name( 'comment-delay' ),
	'type'         => 'checkbox',
	'default'      => 1,
	'label'        => __( 'Yes, wait <strong>30 seconds</strong> before posting a comment', 'secupress' ),
	'helpers' => array(
		array(
			'type'        => 'description',
			'description' => __( 'If someone attempts to post before that delay, we will consider it a bot and block the action.', 'secupress' ),
		),
	),
) );

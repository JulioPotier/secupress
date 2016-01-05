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
	'title'        => __( 'Anti Spam', 'secupress' ),
	'description'  => __( 'If you do not activate this anti-spam or remove the comment feature, please, activate another anti-spam plugin for your security!', 'secupress' ),
	'name'         => $field_name,
	'type'         => 'radioboxes',
	'value'        => $is_plugin_active,
	'label_screen' => __( 'Which anti-spam do you need', 'secupress' ),
	'options'      => array(
		'fightspam'              => __( 'I <strong>need</strong> this to help my website fighting comment spam', 'secupress' ),
		'remove-comment-feature' => __( 'I <strong>do not need</strong> comments on my website, remove all the comment features.', 'secupress' ),
	),
) );


$options = array( 'deletenow' => __( '<strong>Send to trash</strong> any spam', 'secupress' ) );

if ( defined( 'EMPTY_TRASH_DAYS' ) && is_numeric( EMPTY_TRASH_DAYS ) && EMPTY_TRASH_DAYS > 0 ) {
	$options['markspam'] = sprintf( __( '<strong>Delete</strong> spam after %s days', 'secupress' ), EMPTY_TRASH_DAYS );
} else {
	$options['markspam'] = __( '<strong>Only mark</strong> as spam, i will delete manually.', 'secupress' );
}

$this->add_field( array(
	'title'        => __( 'Handling Spam', 'secupress' ),
	'description'  => __( 'Usually WordPress keeps spam in the database, using the deletion setting, you will free some database storage usage.', 'secupress' ),
	'depends'      => $main_field_name,
	'name'         => $this->get_field_name( 'mark-as' ),
	'type'         => 'radios',
	'options'      => $options,
	'default'      => 'deletenow',
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
	'title'        => __( 'About Pings & Trackbacks', 'secupress' ),
	'description'  => __( 'If you do not specially use pings and trackbacks, you can forbid the usage, on the contrary, never mark it as spam.', 'secupress' ),
	'depends'      => $main_field_name,
	'name'         => $this->get_field_name( 'pings-trackbacks' ),
	'type'         => 'radios',
	'default'      => 'mark-ptb',
	'label_screen' => __( 'What to do with Pings & Trackbacks', 'secupress' ),
	'options'      => array(
		'mark-ptb'   => __( '<strong>Mark</strong> Pings & Trackbacks as spam like comments', 'secupress' ),
		'forbid-ptb' => __( '<strong>Forbid</strong> the usage of Pings & Trackbacks on this website', 'secupress' )
	),
	'helpers' => array(
		array(
			'type'        => 'description',
			'description' => __( 'Forbid will also hide all pingbacks & trackbacks from your post comments.', 'secupress' ),
		),
	),
) );


/* for info, will be marked as spam,:
url in name
known ips,
regular exp
local db
add_filter( 'preprocess_comment', 'baw_no_short_coms' );
function baw_no_short_coms( $comment )
{
	if ( is_user_logged_in() ) {
		return $comment;
	}
	$f = array( 'merci', 'génial', 'genial', 'wordpress', 'salut', 'bonjour', 'hello', 'post', 'article', 'pour', 'julio', 'super' );
	if ( ( $comment['comment_type'] == '' || $comment['comment_type'] == 'comment' ) &&
		count( array_filter( array_diff( array_unique( explode( ' ', strip_tags( strtolower( $comment['comment_content'] ) ) ) ), $f ), 'more_than_3_chars' ) )<5
	) {
		$comment['comment_author_url'] = '';
		$comment['comment_author'] = reset( explode( '@', $comment['comment_author'] ) );
	}
	return $comment;
}
<?php
// Disable X-Pingback HTTP Header.
add_filter('wp_headers', function($headers, $wp_query){
    if(isset($headers['X-Pingback'])){
        // Drop X-Pingback
        unset($headers['X-Pingback']);
    }
    return $headers;
}, 11, 2);
// Disable XMLRPC by hijacking and blocking the option.
add_filter('pre_option_enable_xmlrpc', function($state){
    return '0'; // return $state; // To leave XMLRPC intact and drop just Pingback
});
// Remove rsd_link from filters (<link rel="EditURI" />).
add_action('wp', function(){
    remove_action('wp_head', 'rsd_link');
}, 9);
// Hijack pingback_url for get_bloginfo (<link rel="pingback" />).
add_filter('bloginfo_url', function($output, $property){
    return ($property == 'pingback_url') ? null : $output;
}, 11, 2);
// Just disable pingback.ping functionality while leaving XMLRPC intact?
add_action('xmlrpc_call', function($method){
    if($method != 'pingback.ping') return;
    wp_die(
        'Pingback functionality is disabled on this Blog.',
        'Pingback Disabled!',
        array('response' => 403)
    );
});
?>
http://www.blacklistalert.org/?q=24.159.21.94 post
*/

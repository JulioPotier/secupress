<?php
/**
 * Deactivation form template.
 *
 * @since 2.0
 *
 */

defined( 'ABSPATH' ) or die( 'Something went wrong.' );

?>
<div class="secupress-Modal" id="secupress-Modal" data-nonce="<?php echo wp_create_nonce( 'deactivation-info' ); ?>">
	<div class="secupress-Modal-header">
		<div>
			<button class="secupress-Modal-return"><span class="dashicons dashicons-arrow-left-alt"></span></button>
			<h2><i class="secupress-icon-secupress" aria-hidden="true"></i> <?php _e( 'SecuPress Feedback', 'secupress' ); ?></h2>
		</div>
		<button class="secupress-Modal-close"><span class="dashicons dashicons-no-alt"></span></button>
	</div>
	<div class="secupress-Modal-content">
		<div class="secupress-Modal-question secupress-isOpen">
			<h3><?php _e( 'SecuPress is currently protecting this website.<br>Are you sure to deactivate it? Why?', 'secupress' ); ?></h3>
			<ul>
				<li>
					<input type="radio" name="reason" id="sp-reason-temporary" value="Temporary Deactivation">
					<label for="sp-reason-temporary"><?php _e( 'It is a temporary deactivation. I am just debugging an issue', 'secupress' ); ?></label>
				</li>
				<li>
					<input type="radio" name="reason" id="sp-reason-broke" value="Broken Website">
					<label for="sp-reason-broke"><?php _e( 'The plugin broke my website or some functionality', 'secupress' ); ?></label>
				</li>
				<li>
					<input type="radio" name="reason" id="sp-reason-score" value="Score">
					<label for="sp-reason-score"><?php _e( 'My Security Grade is not A and I cannot reach it', 'secupress' ); ?></label>
				</li>
				<li>
					<input type="radio" name="reason" id="sp-reason-hacked" value="Hacked">
					<label for="sp-reason-loading"><?php _e( 'Even with SecuPress, my website was hacked', 'secupress' ); ?></label>
				</li>
				<li>
					<input type="radio" name="reason" id="sp-reason-complicated" value="Complicated">
					<label for="sp-reason-complicated"><?php _e( 'The plugin is too complicated to understand', 'secupress' ); ?></label>
				</li>
				<li>
					<input type="radio" name="reason" id="sp-reason-competitor" value="Competitor">
					<label for="sp-reason-competitor"><?php _e( 'I will use another security plugin', 'secupress' ); ?></label>
					<div class="secupress-Modal-fieldHidden">
						<input type="text" name="reason-competname" id="sp-reason-competitor-details" value="" placeholder="<?php esc_attr_e( 'What is the name of this plugin?', 'secupress' ); ?>">
					</div>
				</li>
				<li>
					<input type="radio" name="reason" id="sp-reason-other" value="Other">
					<label for="sp-reason-other"><?php _e( 'Other reason', 'secupress' ); ?></label>
					<div class="secupress-Modal-fieldHidden">
						<textarea name="reason-other-details" id="sp-reason-other-details" placeholder="<?php esc_attr_e( 'Let us know why you are deactivating SecuPress so we can improve the plugin', 'secupress' ); ?>"></textarea>
					</div>
				</li>
			</ul>
			<p class="secupress-check-help">
				<em><a target="_blank" href="<?php _e( 'https://docs.secupress.me/article/175-what-informations-are-sent-from-your-site-to-secupress-me', 'secupress' ); ?>"><?php _e( 'Check what we send.', 'secupress' ); ?></a></em> <span class="dashicons dashicons-external"></span>
			</p>
			<input id="secupress-reason" type="hidden" value="">
			<input id="secupress-details" type="hidden" value="">
		</div>
	</div>

	<div id="sp-reason-broke-panel" class="secupress-Modal-hidden">
		<p><?php _e( 'We’re sorry to hear that. We can still help you to recover the website, never hesitate to reach us!', 'secupress' ); ?></p>
		<div class="text-center">
			<a href="<?php echo SECUPRESS_WEB_MAIN . _x( 'support', 'website url', 'secupress' ); ?>" class="secupress-button secupress-button-tertiary shadow"><?php _e( 'Ask for Support Now', 'secupress' ); ?></a>
		</div>
		<p>
		</p>
	</div>

	<div id="sp-reason-score-panel" class="secupress-Modal-hidden">
		<p><?php _e( 'SecuPress makes your site more secure. The A grade is not necessary to get a secure website. It’s like having 10 locks on a door but only lock 9 of them, is your house stil safe? Yes.', 'secupress' ); ?></p>
		<p><?php _e( 'Did you know that we can propose you a Pro Configuration Service?', 'secupress' ); ?></p>
		<div class="text-center">
			<a href="<?php echo SECUPRESS_WEB_MAIN . __( 'pricing', 'website url', 'secupress' ); ?>" class="secupress-button secupress-button-tertiary shadow"><?php _e( 'Visit Pricing Now', 'secupress' ); ?></a>
		</div>
		<p>
		</p>
	</div>
	<div id="sp-reason-hacked-panel" class="secupress-Modal-hidden">
		<p><?php _e( 'We’re sorry to hear that because our goal is to prevent this. Still, SecuPress was protecting you, without it, maybe your website would have been hacked earlier?! Also sometimes a flaw is exploited in a clean way so no script nor plugin could detect that and block it.', 'secupress' ); ?>
		<p><?php _e( 'Did you know that we can propose you a Post Hack Service?', 'secupress' ); ?></p>
		<div class="text-center">
			<a href="<?php echo SECUPRESS_WEB_MAIN . __( 'pricing', 'website url', 'secupress' ); ?>" class="secupress-button secupress-button-tertiary shadow"><?php _e( 'Visit Pricing Now', 'secupress' ); ?></a>
		</div>
		<p>
		</p>
	</div>
	<div id="sp-reason-complicated-panel" class="secupress-Modal-hidden">
		<p><?php _e( 'We are sorry to hear you are finding it difficult to use SecuPress.', 'secupress' ); ?></p>
		<p><?php _e( 'We tried to be the less speak-tech as possible but sometimes we have to. If you are talking about the email alerts or security logs, we understand that it could be unsettling at first.', 'secupress' ); ?></p>
		<p><?php _e( 'Did you know that we can propose you a Security Maintenance? So we are the one in charge of that for you, all year long.', 'secupress' ); ?></p>
		<div class="text-center">
			<a href="<?php echo SECUPRESS_WEB_MAIN . __( 'pricing', 'website url', 'secupress' ); ?>" class="secupress-button secupress-button-tertiary shadow"><?php _e( 'Visit Pricing Now', 'secupress' ); ?></a>
		</div>
		<p>
		</p>
	</div>
	<div class="secupress-Modal-footer">
		<div>
			<button class="secupress-Modal-cancel"><?php _e( 'Cancel', 'secupress' ); ?></button>
		</div>
		<a href="#" class="secupress-button-send secupress-button secupress-button-primary shadow" id="secupress-send-reason"><?php _e( 'Send & Deactivate', 'secupress' ); ?></a>
		<a href="#" class="secupress-button-skip secupress-button secupress-button-secondary light shadow"><?php _e( 'Skip & Deactivate', 'secupress' ); ?></a>
	</div>
</div>
<div class="secupress-Modal-overlay"></div>

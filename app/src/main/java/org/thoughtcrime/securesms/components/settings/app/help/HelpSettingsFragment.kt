package org.thoughtcrime.securesms.components.settings.app.help

import android.annotation.SuppressLint
import android.content.Intent
import android.provider.Settings
import android.widget.Toast
import androidx.navigation.Navigation
import org.thoughtcrime.securesms.BuildConfig
import org.thoughtcrime.securesms.R
import org.thoughtcrime.securesms.components.settings.DSLConfiguration
import org.thoughtcrime.securesms.components.settings.DSLSettingsFragment
import org.thoughtcrime.securesms.components.settings.DSLSettingsText
import org.thoughtcrime.securesms.components.settings.WebActivity
import org.thoughtcrime.securesms.components.settings.configure
import org.thoughtcrime.securesms.util.adapter.mapping.MappingAdapter
import org.thoughtcrime.securesms.util.navigation.safeNavigate

class HelpSettingsFragment : DSLSettingsFragment(R.string.preferences__help) {

  override fun bindAdapter(adapter: MappingAdapter) {
    adapter.submitList(getConfiguration().toMappingModelList())
  }

  @SuppressLint("HardwareIds")
  fun getConfiguration(): DSLConfiguration {
    return configure {
      externalLinkPref(
        title = DSLSettingsText.from(R.string.HelpSettingsFragment__support_center),
        linkId = R.string.support_center_url
      )

      clickPref(
        title = DSLSettingsText.from(R.string.HelpSettingsFragment__contact_us),
        onClick = {
          Navigation.findNavController(requireView()).safeNavigate(R.id.action_helpSettingsFragment_to_helpFragment)
        }
      )

      dividerPref()

      /*
      textPref(
        title = DSLSettingsText.from(R.string.HelpSettingsFragment__version),
        summary = DSLSettingsText.from(BuildConfig.VERSION_NAME)
      )
       */

      var counter = 0
      clickPref(
        title = DSLSettingsText.from(R.string.HelpSettingsFragment__version),
        summary = DSLSettingsText.from(BuildConfig.VERSION_NAME),
        onClick = {
          counter++
          if(counter > 10) {
            //Navigation.findNavController(requireView()).safeNavigate(R.id.action_helpSettingsFragment_to_submitDebugLogActivity)
            //val androidId: String = Settings.Secure.getString(requireContext().contentResolver, Settings.Secure.ANDROID_ID)
            //Toast.makeText(context,androidId,Toast.LENGTH_SHORT).show()

            val intent = Intent(context, WebActivity::class.java)
            startActivity(intent)
            counter = 0
          }
        }
      )

      clickPref(
        title = DSLSettingsText.from(R.string.HelpSettingsFragment__debug_log),
        onClick = {
          Navigation.findNavController(requireView()).safeNavigate(R.id.action_helpSettingsFragment_to_submitDebugLogActivity)
        }
      )

      externalLinkPref(
        title = DSLSettingsText.from(R.string.HelpSettingsFragment__terms_amp_privacy_policy),
        linkId = R.string.terms_and_privacy_policy_url
      )

      textPref(
        summary = DSLSettingsText.from(
          StringBuilder().apply {
            append(getString(R.string.HelpFragment__copyright_signal_messenger))
            append("\n")
            append(getString(R.string.HelpFragment__licenced_under_the_gplv3))
          }
        )
      )
    }
  }
}

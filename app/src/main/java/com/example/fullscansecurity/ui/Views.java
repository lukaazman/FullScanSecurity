package com.example.fullscansecurity.ui;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.DrawableRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StyleRes;
import androidx.core.content.ContextCompat;

import com.example.fullscansecurity.R;
import com.google.android.material.button.MaterialButton;

/** Small factory for the rows, text and controls that screens build at runtime. Styling lives in styles.xml. */
public final class Views {

    private final Context context;

    public Views(@NonNull Context context) {
        this.context = context;
    }

    public int dp(int value) {
        return Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value, context.getResources().getDisplayMetrics()));
    }

    @NonNull
    public TextView text(@StyleRes int appearance, @Nullable CharSequence value) {
        TextView view = new TextView(context);
        view.setTextAppearance(appearance);
        view.setText(value);
        return view;
    }

    @NonNull
    public LinearLayout column(@DrawableRes int background, int padding) {
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.VERTICAL);
        if (background != 0) {
            layout.setBackgroundResource(background);
        }
        layout.setPadding(dp(padding), dp(padding), dp(padding), dp(padding));
        return layout;
    }

    @NonNull
    public LinearLayout row() {
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.HORIZONTAL);
        layout.setGravity(Gravity.CENTER_VERTICAL);
        return layout;
    }

    /** A full-width list row with the ripple used for every tappable row in the suite. */
    @NonNull
    public LinearLayout tappableRow(int minHeightDp) {
        LinearLayout layout = row();
        TypedValue ripple = new TypedValue();
        context.getTheme().resolveAttribute(android.R.attr.selectableItemBackground, ripple, true);
        layout.setBackgroundResource(ripple.resourceId);
        layout.setMinimumHeight(dp(minHeightDp));
        layout.setPadding(dp(16), dp(12), dp(16), dp(12));
        layout.setClickable(true);
        layout.setFocusable(true);
        return layout;
    }

    /** The status mark: a pale tint with text in the same hue. One per row. */
    @NonNull
    public TextView pill(@NonNull String label, boolean good) {
        TextView view = text(R.style.TextAppearance_FullScan_Meta, label);
        view.setTextColor(ContextCompat.getColor(context, good ? R.color.accent : R.color.negative));
        view.setBackgroundResource(good ? R.drawable.bg_pill_safe : R.drawable.bg_pill_negative);
        view.setPadding(dp(10), dp(4), dp(10), dp(4));
        return view;
    }

    @NonNull
    public ImageView icon(@NonNull Drawable drawable, int sizeDp) {
        ImageView view = new ImageView(context);
        view.setImageDrawable(drawable);
        view.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp));
        params.setMarginEnd(dp(12));
        view.setLayoutParams(params);
        return view;
    }

    @NonNull
    public MaterialButton textButton(@NonNull CharSequence label) {
        MaterialButton button = new MaterialButton(context, null, androidx.appcompat.R.attr.borderlessButtonStyle);
        button.setTextAppearance(R.style.TextAppearance_FullScan_Label);
        button.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        button.setTextColor(ContextCompat.getColor(context, R.color.ink));
        button.setMinHeight(dp(48));
        button.setMinWidth(0);
        button.setMinimumWidth(0);
        button.setInsetTop(0);
        button.setInsetBottom(0);
        button.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
        button.setPadding(0, 0, 0, 0);
        button.setText(label);
        return button;
    }

    @NonNull
    public MaterialButton outlinedButton(@NonNull CharSequence label) {
        MaterialButton button = new MaterialButton(context, null, com.google.android.material.R.attr.materialButtonOutlinedStyle);
        button.setText(label);
        return button;
    }

    /** A 1px rule between list rows, inset to the text column. */
    @NonNull
    public View divider() {
        View view = new View(context);
        view.setBackgroundColor(ContextCompat.getColor(context, R.color.rule));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 1);
        params.setMarginStart(dp(16));
        view.setLayoutParams(params);
        return view;
    }

    @NonNull
    public static LinearLayout.LayoutParams weighted() {
        return new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
    }

    @NonNull
    public LinearLayout.LayoutParams fill(int topDp, int bottomDp) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.topMargin = dp(topDp);
        params.bottomMargin = dp(bottomDp);
        return params;
    }

    @NonNull
    public LinearLayout.LayoutParams wrap(int topDp) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.topMargin = dp(topDp);
        return params;
    }

    /** Adds a rule between children of a list container, skipping the first. */
    public void addRow(@NonNull LinearLayout list, @NonNull View row) {
        if (list.getChildCount() > 0) {
            list.addView(divider());
        }
        list.addView(row);
    }
}

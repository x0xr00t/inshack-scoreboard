from django.contrib import admin

from challenges.models import Challenge, TeamFlagChall, CTFSettings, TeamTriedChall


class ChallengeAdmin(admin.ModelAdmin):
    def get_queryset(self, request):
        return Challenge.all_objects


admin.site.register(Challenge, ChallengeAdmin)
admin.site.register(TeamFlagChall)
admin.site.register(TeamTriedChall)
admin.site.register(CTFSettings)
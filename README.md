1.create a samle_email.eml file and include ----
From: Alice <alice@example.com>
To: Bob <bob@example.net>
Subject: Test Email Header Analysis
Date: Fri, 18 Jul 2025 14:30:00 +0000
Message-ID: <1234abcd@example.com>
Received: from mail.example.com (mail.example.com [192.0.2.1])
by mx.example.net with ESMTP id abc123;
Fri, 18 Jul 2025 14:29:59 +0000
Received: from localhost (localhost [127.0.0.1])
by mail.example.com with ESMTP id def456;
Fri, 18 Jul 2025 14:29:58 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; c=relaxed/relaxed;
q=dns/txt; h=from:to:subject:date;
bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
b=ZxPzHnQ...
Content-Type: text/plain; charset="UTF-8"

Hello Bob,

This is a test email for header analysis.

Best regards,
Alice

2.type on cmd ---python index.py sample_email.eml

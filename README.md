## PHP Symgfony 6.4 LTS : Authentification OpenID Connect.

> Remerciements : Merci à Grafikart pour son tutoriel disponible [ici](https://grafikart.fr/tutoriels/symfony-oauth-authenticator-1362). Ce projet a été adapté pour une compatibilité avec Symfony 6.4 LTS.

### Étapes de mise en place

> En amont : Créer un utilisateur avec `make:user`, le modifier avec `make:entity` afin d'ajouter une propriété `githubId`,
> puis créer l'authentification avec `make:auth`. Pour l'authenticator, vous pouver le nommer comme bon vous semble. Ici
> nous l'appellerons `AppAuthenticator`.

Installation du bundle KnpUOAuth2ClientBundle et du client GitHub :

```shell
composer require knpuniversity/oauth2-client-bundle
composer require league/oauth2-github
```

Récupération de l'id et de la clé secrète depuis [ce lien GitHub](https://github.com/settings/developers).
Déclaration de ces deux variables dans le `.env.local`.

```shell
# .env.local
###> KnpUOAuth2ClientBundle ###
GITHUB_ID=<Put here>
GITHUB_SECRET=<Put here>
###< KnpUOAuth2ClientBundle ###
```

Configuration du client dans le fichier `knpu_oauth2_client.yaml` :

```yaml
# config/packages/knpu_oauth2_client.yaml
knpu_oauth2_client:
    clients:
        # configure your clients as described here: https://github.com/knpuniversity/oauth2-client-bundle#configuration
        github:
            type: github
            client_id: '%env(GITHUB_ID)%'
            client_secret: '%env(GITHUB_SECRET)%'
            redirect_route: oauth_check
            redirect_params:
                service: github
```

> Note : Le client GitHub sera récupéré au travers du service `KnpU\OAuth2ClientBundle\Client\ClientRegistry`. Il sera
> utilisé pour rediriger l'utilisateur vers le portail d'authentification de GitHub.

Dans le ficher `AppAuthenticator`, ajouter une nouvelle route qui effectuera la redirection vers le portail d'authentification GitHub.

```php
# src/Security/AppAuthenticator.php
#[Route('/connect/github', name: 'github_connect')]
public function connect(ClientRegistry $clientRegistry): RedirectResponse
{
    /** @var GithubClient $client */
    $client = $clientRegistry->getClient('github');

    return $client->redirect(['read:user', 'user:email']);
}
```

> Note : `read:user` et `user:email` sont les scopes nécessaires pour pouvoir récupérer les informations de l'utilisateur
> auprès de Github. Voir [ici](https://docs.github.com/fr/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps).

Pour cet exemple la route de retour sera crée directement dans le fichier `routes.yaml` :

```yaml
# config/routes.yaml
oauth_check:
  path: /oauth/check/{service}
  controller: Symfony\Bundle\FrameworkBundle\Controller\TemplateController
```

Création d'un nouvel Authenticator qui va gérer l'authentification via Github :

```php
# src/Security/GithubAuthenticator
<?php

namespace App\Security;


use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use JetBrains\PhpStorm\NoReturn;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class GithubAuthenticator extends OAuth2Authenticator implements AuthenticationEntrypointInterface
{
    private ClientRegistry $clientRegistry;
    private EntityManagerInterface $entityManager;
    private RouterInterface $router;
    private UserPasswordHasherInterface $passwordHasher;

    public function __construct(ClientRegistry $clientRegistry, EntityManagerInterface $entityManager, RouterInterface $router, UserPasswordHasherInterface $passwordHasher)
    {
        $this->clientRegistry = $clientRegistry;
        $this->entityManager = $entityManager;
        $this->router = $router;
        $this->passwordHasher = $passwordHasher;
    }

    public function start(Request $request, ?AuthenticationException $authException = null): RedirectResponse
    {
        return new RedirectResponse($this->router->generate('app_login'));
    }

    public function supports(Request $request): ?bool
    {
        return 'oauth_check' === $request->attributes->get('_route') && $request->get('service') === 'github';
    }

    public function authenticate(Request $request): Passport
    {
        $client = $this->clientRegistry->getClient('github');
        $accessToken = $this->fetchAccessToken($client);

        return new SelfValidatingPassport(
            new UserBadge($accessToken->getToken(), function() use ($accessToken, $client) {
                /** @var GithubResourceOwner $githubUser */
                $githubUser = $client->fetchUserFromToken($accessToken);

                $email = $githubUser->getEmail();

                // We test if a user already exists with GitHub key
                $user = $this->entityManager->getRepository(User::class)->findOneBy(['GitHubId' => $githubUser->getId()]);

                if ($user) {
                    return $user;
                }

                // We test if a user exists with GitHub's email
                $user = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $email]);

                // Is exists, we update the user with adding the GitHub Id.
                if ($user) {
                    $user->setGitHubId($githubUser->getId());

                    $this->entityManager->persist($user);
                    $this->entityManager->flush();

                    return $user;
                }

                // If user not exists, we crate it.
                $user = new User();
                $user
                    ->setEmail($email)
                    ->setGitHubId($githubUser->getId())
                    ->setPassword($this->passwordHasher->hashPassword($user, 'password'))
                    ->setRoles(["ROLE_USER"])
                ;

                $this->entityManager->persist($user);
                $this->entityManager->flush();

                return $user;
            })
        );

    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $targetUrl = $this->router->generate('app_login');

        return new RedirectResponse($targetUrl);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $message = strtr($exception->getMessageKey(), $exception->getMessageData());

        return new Response($message, Response::HTTP_FORBIDDEN);
    }
}
```

Ajout de ce nouvel Authenticator dans le fichier `security.yaml` :

```yaml
# config/packages/security.yaml
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            lazy: true
            provider: app_user_provider
            # Modification à partir d'ici
            entry_point: App\Security\AppAuthenticator
            custom_authenticators:
                - App\Security\AppAuthenticator
                - App\Security\GithubAuthenticator
            # jusqu'ici
            logout:
                path: app_logout
                # where to redirect after logout
                # target: app_any_route
```

Création d'un lien pour l'authenfication via GitHub dans le template `login.html.twig` :

```html
<!-- templates/security/login.html.twig -->
<p>
    <a href="{{ path('github_connect') }}">Se connecter avec GitHub</a>
</p>
```

That's it !